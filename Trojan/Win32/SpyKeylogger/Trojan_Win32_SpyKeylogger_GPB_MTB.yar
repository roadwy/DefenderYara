
rule Trojan_Win32_SpyKeylogger_GPB_MTB{
	meta:
		description = "Trojan:Win32/SpyKeylogger.GPB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {49 00 44 00 5c 00 7b 00 } //2 ID\{
		$a_01_1 = {08 1a 74 25 e8 42 c3 89 4b b8 48 24 2a 79 40 97 72 e1 2f 7c 0c 90 0e c8 c6 8f 06 b0 b6 74 5f aa ec f3 d7 b1 70 13 5f 81 8a 05 96 80 57 f4 20 4f e5 53 3f 49 dd 03 2f be 63 03 17 58 92 98 95 63 } //2
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}