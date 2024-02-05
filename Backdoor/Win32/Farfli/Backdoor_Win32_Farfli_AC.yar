
rule Backdoor_Win32_Farfli_AC{
	meta:
		description = "Backdoor:Win32/Farfli.AC,SIGNATURE_TYPE_PEHSTR_EXT,fffffffa 00 ffffffdc 00 05 00 00 64 00 "
		
	strings :
		$a_01_0 = {c6 85 dc fe ff ff 61 c6 85 dd fe ff ff 76 c6 85 de fe ff ff 70 c6 85 df fe ff ff 2e c6 85 e0 fe ff ff 65 } //64 00 
		$a_01_1 = {c6 85 35 fe ff ff 75 c6 85 36 fe ff ff 63 c6 85 37 fe ff ff 6b c6 85 38 fe ff ff 33 c6 85 39 fe ff ff 36 } //32 00 
		$a_01_2 = {42 00 99 b9 19 00 00 00 f7 f9 83 c2 61 52 8d 95 64 fe ff ff 52 68 } //32 00 
		$a_01_3 = {c6 45 85 50 c6 45 86 4d c6 45 87 4f c6 45 88 4e c6 45 89 2e c6 45 8a 45 c6 45 8b 58 } //14 00 
		$a_01_4 = {c6 45 90 4d c6 45 91 58 c6 45 92 57 c6 45 93 4c c6 45 94 56 c6 45 95 49 c6 45 96 50 } //00 00 
		$a_00_5 = {87 10 00 00 f9 f6 f1 fc be f8 6c 06 28 56 e5 c1 fb 15 01 00 } //87 10 
	condition:
		any of ($a_*)
 
}