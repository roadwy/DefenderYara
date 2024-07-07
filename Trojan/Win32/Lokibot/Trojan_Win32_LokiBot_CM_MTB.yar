
rule Trojan_Win32_LokiBot_CM_MTB{
	meta:
		description = "Trojan:Win32/LokiBot.CM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 03 00 00 "
		
	strings :
		$a_03_0 = {8b c1 6a 0c 99 5e f7 fe 8a 82 90 01 04 30 04 0f 41 3b cb 72 90 00 } //5
		$a_81_1 = {47 65 74 54 69 63 6b 43 6f 75 6e 74 } //1 GetTickCount
		$a_81_2 = {44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 } //1 DllRegisterServer
	condition:
		((#a_03_0  & 1)*5+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1) >=7
 
}