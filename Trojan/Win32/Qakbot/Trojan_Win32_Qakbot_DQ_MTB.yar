
rule Trojan_Win32_Qakbot_DQ_MTB{
	meta:
		description = "Trojan:Win32/Qakbot.DQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 06 00 00 "
		
	strings :
		$a_01_0 = {44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 } //10 DllRegisterServer
		$a_01_1 = {53 6c 75 65 56 2e 64 6c 6c } //1 SlueV.dll
		$a_01_2 = {45 78 78 58 62 6a 75 6f } //1 ExxXbjuo
		$a_01_3 = {4e 73 67 7a 61 63 54 6f 61 } //1 NsgzacToa
		$a_01_4 = {59 69 4c 79 73 68 6f 4b 70 6a } //1 YiLyshoKpj
		$a_01_5 = {64 64 7a 49 7a 55 72 76 66 74 } //1 ddzIzUrvft
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=15
 
}