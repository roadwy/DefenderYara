
rule Trojan_Win32_ThemidaPacked_PK_MTB{
	meta:
		description = "Trojan:Win32/ThemidaPacked.PK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {86 0b 10 74 b2 15 08 72 aa 13 1c d7 31 15 02 d4 84 0b 4f } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}