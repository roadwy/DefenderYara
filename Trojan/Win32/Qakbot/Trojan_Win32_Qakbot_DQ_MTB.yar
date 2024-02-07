
rule Trojan_Win32_Qakbot_DQ_MTB{
	meta:
		description = "Trojan:Win32/Qakbot.DQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 06 00 00 0a 00 "
		
	strings :
		$a_01_0 = {44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 } //01 00  DllRegisterServer
		$a_01_1 = {53 6c 75 65 56 2e 64 6c 6c } //01 00  SlueV.dll
		$a_01_2 = {45 78 78 58 62 6a 75 6f } //01 00  ExxXbjuo
		$a_01_3 = {4e 73 67 7a 61 63 54 6f 61 } //01 00  NsgzacToa
		$a_01_4 = {59 69 4c 79 73 68 6f 4b 70 6a } //01 00  YiLyshoKpj
		$a_01_5 = {64 64 7a 49 7a 55 72 76 66 74 } //00 00  ddzIzUrvft
	condition:
		any of ($a_*)
 
}