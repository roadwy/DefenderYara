
rule Trojan_Win32_Danabot_OY_MTB{
	meta:
		description = "Trojan:Win32/Danabot.OY!MTB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {8b 4d fc 03 cf 30 01 b8 01 00 00 00 83 f0 04 83 6d fc 01 39 75 fc 7d e3 5f 5e c9 c3 } //1
		$a_01_1 = {53 65 74 50 72 6f 63 65 73 73 53 68 75 74 64 6f 77 6e 50 61 72 61 6d 65 74 65 72 73 } //1 SetProcessShutdownParameters
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}