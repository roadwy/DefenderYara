
rule Trojan_Win32_Ardamax_DB_MTB{
	meta:
		description = "Trojan:Win32/Ardamax.DB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {8b 4c 24 1c 8a 1c 3e 8b c6 83 e0 7f 8a 14 08 8b c6 32 d3 83 e0 07 b9 08 00 00 00 8a da 2b c8 d2 e3 8a c8 d2 ea 0a da 88 1c 3e 46 3b f5 72 d1 } //2
		$a_01_1 = {43 3a 5c 66 69 6c 65 2e 65 78 65 } //2 C:\file.exe
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}