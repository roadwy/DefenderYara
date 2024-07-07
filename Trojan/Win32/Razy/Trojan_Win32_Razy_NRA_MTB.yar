
rule Trojan_Win32_Razy_NRA_MTB{
	meta:
		description = "Trojan:Win32/Razy.NRA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {0f 87 84 08 00 00 3b 74 24 90 01 01 0f 87 7a 08 00 00 c1 e8 90 01 01 83 e3 0f 2e ff 24 9d 90 01 04 87 db 8b 06 8d 76 90 01 01 8b d8 d1 d8 90 00 } //5
		$a_01_1 = {69 62 69 6c 6c 69 6e 67 73 79 73 74 65 6d 73 } //1 ibillingsystems
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}