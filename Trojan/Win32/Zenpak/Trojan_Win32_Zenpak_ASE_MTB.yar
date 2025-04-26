
rule Trojan_Win32_Zenpak_ASE_MTB{
	meta:
		description = "Trojan:Win32/Zenpak.ASE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {8b 55 e8 8b 75 d0 8a 14 32 32 14 0b 8b 4d e4 88 14 31 } //1
		$a_01_1 = {77 00 41 00 77 00 61 00 74 00 65 00 72 00 73 00 6d 00 6f 00 76 00 69 00 6e 00 67 00 2e 00 66 00 6f 00 72 00 66 00 69 00 72 00 73 00 74 00 36 00 } //1 wAwatersmoving.forfirst6
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}