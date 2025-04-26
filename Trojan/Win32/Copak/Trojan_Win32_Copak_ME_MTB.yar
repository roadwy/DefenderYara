
rule Trojan_Win32_Copak_ME_MTB{
	meta:
		description = "Trojan:Win32/Copak.ME!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {41 81 c7 58 54 ed 46 81 ef 1d 7f 5d 19 68 d8 85 40 00 5b 81 e9 c9 15 e4 85 09 f9 e8 16 00 00 00 31 1a 68 4c 27 fc d9 59 42 81 e9 28 ef 66 11 39 f2 75 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}