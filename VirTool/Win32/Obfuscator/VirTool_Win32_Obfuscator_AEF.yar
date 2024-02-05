
rule VirTool_Win32_Obfuscator_AEF{
	meta:
		description = "VirTool:Win32/Obfuscator.AEF,SIGNATURE_TYPE_PEHSTR,1e 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {81 75 ec 69 c3 98 e7 e9 24 01 00 00 66 81 4d fe 5c cc dd 45 f4 e8 d1 35 00 00 66 31 45 fe 8a 55 f3 08 55 fd e8 8a fe ff ff be 84 a7 40 00 8d 7d b4 b9 04 00 00 00 f3 a5 81 75 ec 75 cb ae fd e9 } //01 00 
		$a_01_1 = {c7 45 e0 a0 02 00 00 81 75 ec 9e 30 9e 39 eb 6c 33 c0 8a 45 fd 33 c9 8a 4d f3 f7 e9 88 45 fd e8 63 fe ff ff 69 45 dc de 33 48 00 } //00 00 
	condition:
		any of ($a_*)
 
}