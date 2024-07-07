
rule VirTool_WinNT_Dogrobot_gen_J{
	meta:
		description = "VirTool:WinNT/Dogrobot.gen!J,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {c6 45 e8 8b c6 45 ea 55 c6 45 eb 8b c6 45 ec ec c6 45 f0 e9 0f 85 90 01 02 00 00 ff 15 90 01 04 88 45 ff fa 0f 20 c0 25 ff ff fe ff 0f 22 c0 90 00 } //1
		$a_01_1 = {4f 62 52 65 66 65 72 65 6e 63 65 4f 62 6a 65 63 74 42 79 48 61 6e 64 6c 65 } //1 ObReferenceObjectByHandle
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}