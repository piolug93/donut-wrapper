from mythic_container.PayloadBuilder import *
from mythic_container.MythicCommandBase import *
from mythic_container.MythicRPC import *
import os
import tempfile
import donut


class DonutWrapper(PayloadType):
    name = "donut_wrapper"
    file_extension = "exe"
    author = "piolug93"
    supported_os = [SupportedOS.Windows]
    wrapper = True
    wrapped_payloads = ["apollo", "athena", "merlin"]
    note = "Wrap shellcode files in donut shellcode"
    supports_dynamic_loading = False
    build_parameters = [
        BuildParameter(
            name="output",
            parameter_type=BuildParameterType.String,
            description="Optional output filename for the generated loader. If not provided, defaults to the input filename with an appropriate extension based on the selected format.",
            default_value="",
            ui_position=-1,
            verifier_regex=r"^(?!.*[\\/])(?!.*\.\.)(?!\.)[\w\s-]+(?:\.[A-Za-z0-9]+)?$",
        ),
        BuildParameter(
            name="arch",
            parameter_type=BuildParameterType.ChooseOne,
            description="Target architecture for loader : 1=x86, 2=amd64, 3=x86+amd64(default).",
            choices=["x86", "x64", "x86+amd64"],
            default_value="x86+amd64",
        ),
        BuildParameter(
            name="bypass",
            parameter_type=BuildParameterType.ChooseOne,
            description="Behavior for bypassing AMSI/WLDP/ETW: 1=None, 2=Abort on fail, 3=Continue on fail (default).",
            choices=["none", "abort", "continue"],
            default_value="continue",
        ),
        BuildParameter(
            name="headers",
            parameter_type=BuildParameterType.ChooseOne,
            description="Preserve PE headers. 1=Overwrite (default), 2=Keep all",
            choices=["overwrite", "keep"],
            default_value="overwrite",
        ),
        BuildParameter(
            name="entropy",
            parameter_type=BuildParameterType.ChooseOne,
            description="Entropy: 1=None, 2=Random names, 3=Random names + encryption (default).",
            choices=["none", "random", "random+encrypt"],
            default_value="random+encrypt",
        ),
        BuildParameter(
            name="format",
            parameter_type=BuildParameterType.ChooseOne,
            description="Output format: 1=Binary (default), 2=Base64, 3=C, 4=Ruby, 5=Python, 6=Powershell, 7=C#, 8=Hex, 9=UUID.",
            choices=["binary", "base64", "c", "ruby", "python", "powershell", "csharp", "hex", "uuid"],
            default_value="binary",
        ),
        BuildParameter(
            name="args",
            parameter_type=BuildParameterType.Array,
            description="Optional parameters/command line passed to the payload.",
            default_value=[],
        ),
        BuildParameter(
            name="runtime",
            parameter_type=BuildParameterType.String,
            description="CLR runtime version. MetaHeader used by default or v4.0.30319 if none available.",
            default_value="",
        ),
        BuildParameter(
            name="server",
            parameter_type=BuildParameterType.String,
            description="URL for the HTTP server that will host a Donut module. Credentials may be provided in the following format: http://user:pass@host/path",
            default_value="",
        ),
        BuildParameter(
            name="modname",
            parameter_type=BuildParameterType.String,
            description="Module name for HTTP staging. If entropy is enabled, one is generated randomly.",
            default_value="",
        ),
        BuildParameter(
            name="decoy",
            parameter_type=BuildParameterType.File,
            description="Optional path to a decoy module for module overloading.",
            default_value="",
        ),
        BuildParameter(
            name="cls",
            parameter_type=BuildParameterType.String,
            description="Optional class name. (required for .NET DLL) Can also include namespace: e.g namespace.class",
            default_value="",
        ),
        BuildParameter(
            name="method",
            parameter_type=BuildParameterType.String,
            description="Optional entrypoint (DLL function or .NET method).",
            default_value="",
        ),
        BuildParameter(
            name="domain",
            parameter_type=BuildParameterType.String,
            description="Optional AppDomain name (used for .NET assemblies).",
            default_value="",
        ),
        BuildParameter(
            name="thread",
            parameter_type=BuildParameterType.Boolean,
            description="Run payload entrypoint in a new thread (use -t).",
            default_value="false",
        ),
        BuildParameter(
            name="unicode",
            parameter_type=BuildParameterType.Boolean,
            description="Pass parameters to unmanaged DLL entrypoint in Unicode (use -w).",
            default_value="false",
        ),
        BuildParameter(
            name="exit",
            parameter_type=BuildParameterType.ChooseOne,
            description="Exit behavior: 1=Thread (default), 2=Process, 3=Block.",
            choices=["thread", "process", "block"],
            default_value="thread",
        ),
        BuildParameter(
            name="oep",
            parameter_type=BuildParameterType.String,
            description="Creates a new thread for the loader and continues execution at an address that is an offset relative to the host process's executable. The value provided is the offset. This option supports loaders that wish to resume execution of the host process after donut completes execution.",
            default_value="",
        ),
        BuildParameter(
            name="compress",
            parameter_type=BuildParameterType.ChooseOne,
            description="Pack/Compress the input file. 1=None, 2=aPLib, 3=LZNT1, 4=Xpress, 5=Xpress Huffman. Currently, the last three are only supported on Windows.",
            choices=["none", "aplib", "lznt1", "xpress", "xpress+huffman"],
            default_value="none",
        ),
    ]
    agent_icon_path = Path("../..") / "agent_icons" / "donut.svg" 
    build_steps = [
        BuildStep(step_name="Reading payload", step_description="Reading and saving payload to disk"),
        BuildStep(step_name="Configuring", step_description="Stamping in configuration values"),
        BuildStep(step_name="Generating...", step_description="Generating loader")
    ]

    async def build(self) -> BuildResponse:
        resp = BuildResponse(status=BuildStatus.Error)
        output = ""

        try:
            agent_build_dir = tempfile.TemporaryDirectory(suffix=self.uuid)
            agent_build_path = agent_build_dir.name

            file_name_resp = await SendMythicRPCPayloadSearch(
                MythicRPCPayloadSearchMessage(PayloadUUID=self.wrapped_payload_uuid)
            )
            if file_name_resp.Success and len(file_name_resp.Payloads) > 0:
                payload_name = file_name_resp.Payloads[0].Filename

            input_path = os.path.join(agent_build_path, payload_name)
            with open(input_path, "wb") as f:
                f.write(self.wrapped_payload)
            
            await SendMythicRPCPayloadUpdatebuildStep(MythicRPCPayloadUpdateBuildStepMessage(
                PayloadUUID=self.uuid,
                StepName="Reading payload",
                StepStdout=f"Saved wrapped payload to disk at {input_path}",
                StepSuccess=True
            ))

            kwargs = await self._build_donut_kwargs(
                input_path=input_path,
                agent_build_path=agent_build_path,
            )
            await SendMythicRPCPayloadUpdatebuildStep(MythicRPCPayloadUpdateBuildStepMessage(
                PayloadUUID=self.uuid,
                StepName="Configuring",
                StepStdout=f"Translating build parameters into donut.create kwargs:\n{kwargs}",
                StepSuccess=True
            ))

            try:
                shellcode = donut.create(**kwargs)
                await SendMythicRPCPayloadUpdatebuildStep(MythicRPCPayloadUpdateBuildStepMessage(
                    PayloadUUID=self.uuid,
                    StepName="Generating...",
                    StepStdout=f"Successfully generated loader with donut.create()",
                    StepSuccess=True
                ))
                if isinstance(shellcode, (bytes, bytearray)):
                    with open(kwargs["output"], "rb") as f:
                        resp.payload = f.read()
                    resp.updated_filename = os.path.basename(kwargs.get("output"))
                    resp.status = BuildStatus.Success
                    resp.build_message = "Built using python donut module"
                    return resp
                else:
                    output += "[donut.create error] returned non-bytes\n"
            except Exception as e:
                output += f"[donut.create exception]\n{str(e)}\n"
        except Exception as e:
            resp.build_stderr = output or str(e)
            return resp

    def _get_donut_option_maps(self):
        """Common mapping tables used by both donut.create kwargs and donut.exe CLI args."""
        return {
            "arch": {"x86": "1", "amd64": "2", "x84": "3"},
            "bypass": {"none": "1", "abort": "2", "continue": "3"},
            "headers": {"overwrite": "1", "keep": "2"},
            "entropy": {"none": "1", "random": "2", "random+encrypt": "3"},
            "format": {
                "binary": "1",
                "base64": "2",
                "ruby": "3",
                "c": "4",
                "python": "5",
                "powershell": "6",
                "csharp": "7",
                "hex": "8",
                "uuid": "9",
            },
            "exit": {"thread": "1", "process": "2", "block": "3"},
            "compress": {"none": "1", "aplib": "2", "lznt1": "3", "xpress": "4", "xpress+huffman": "5"},
            "format_extensions": {
                "binary": ".bin",
                "base64": ".b64",
                "c": ".c",
                "ruby": ".rb",
                "python": ".py",
                "powershell": ".ps1",
                "csharp": ".cs",
                "hex": ".hex",
                "uuid": ".uuid",
            },
        }

    def _get_format_extension(self, fmt: str) -> str | None:
        """Return the expected file extension (including dot) for a given donut format."""
        maps = self._get_donut_option_maps()
        return maps.get("format_extensions", {}).get(fmt)

    def _normalize_output_filename(self, out: str, fmt: str) -> str:

        base, ext = os.path.splitext(out)
        expected_ext = self._get_format_extension(fmt)
        if not expected_ext:
            return out

        return base + expected_ext

    async def _build_donut_kwargs(self, input_path: str, agent_build_path: str) -> dict:
        """Construct keyword arguments for donut.create() from Mythic build parameters."""
        maps = self._get_donut_option_maps()
        arch_map = maps["arch"]
        bypass_map = maps["bypass"]
        headers_map = maps["headers"]
        entropy_map = maps["entropy"]
        format_map = maps["format"]
        exit_map = maps["exit"]
        compress_map = maps["compress"]

        kwargs = {"file": input_path}

        arch = self.get_parameter("arch")
        if arch and arch in arch_map:
            kwargs["arch"] = int(arch_map[arch])

        bypass = self.get_parameter("bypass")
        if bypass and bypass in bypass_map:
            kwargs["bypass"] = int(bypass_map[bypass])

        headers = self.get_parameter("headers")
        if headers and headers in headers_map:
            kwargs["headers"] = int(headers_map[headers])

        entropy = self.get_parameter("entropy")
        if entropy and entropy in entropy_map:
            kwargs["entropy"] = int(entropy_map[entropy])

        fmt = self.get_parameter("format")
        if fmt and fmt in format_map:
            kwargs["format"] = int(format_map[fmt])

        out = self.get_parameter("output")
        if out and os.path.isabs(out):
            raise ValueError("Output filename must be a relative path without directory components to prevent writing outside of the build directory.")
        if not out:
            out = os.path.basename(input_path)
            out = self._normalize_output_filename(out, fmt or "binary")
            out = os.path.join(agent_build_path, out)

        out = os.path.join(agent_build_path, out)
        kwargs["output"] = out
            

        args_param = self.get_parameter("args")
        if args_param:
            if isinstance(args_param, (list, tuple)):
                kwargs["params"] = " ".join(str(x) for x in args_param if x is not None)
            else:
                kwargs["params"] = str(args_param)

        runtime = self.get_parameter("runtime")
        if runtime:
            kwargs["runtime"] = runtime

        server = self.get_parameter("server")
        if server:
            kwargs["server"] = server
            kwargs["url"] = server

        modname = self.get_parameter("modname")
        if modname:
            kwargs["modname"] = modname

        ## TODO: dorobić pobieranie decoy z Mythic i zapisywanie go do pliku, a następnie przekazywanie ścieżki do tego pliku w kwargs["decoy"]
        decoy = self.get_parameter("decoy")
        if decoy:
            decoy_resp = await SendMythicRPCFileGetContent(
                MythicRPCFileGetContentMessage(AgentFileID=decoy)
            )
            if decoy_resp.Success and len(decoy_resp.Content) > 0:
                with tempfile.NamedTemporaryFile(delete=False, prefix=f"{decoy}_") as decoy_file:
                    decoy_file.write(decoy_resp.Content)
                    kwargs["decoy"] = decoy_file.name

        cls = self.get_parameter("cls")
        if cls:
            kwargs["cls"] = cls

        method = self.get_parameter("method")
        if method:
            kwargs["method"] = method

        domain = self.get_parameter("domain")
        if domain:
            kwargs["appdomain"] = domain

        if self.get_parameter("thread"):
            kwargs["thread"] = 1

        if self.get_parameter("unicode"):
            kwargs["unicode"] = 1

        exit_opt = self.get_parameter("exit")
        if exit_opt and exit_opt in exit_map:
            kwargs["exit_opt"] = int(exit_map[exit_opt])

        oep = self.get_parameter("oep")
        if oep:
            kwargs["oep"] = oep

        compress = self.get_parameter("compress")
        if compress and compress in compress_map:
            kwargs["compress"] = int(compress_map[compress])

        return kwargs
