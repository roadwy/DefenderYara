
rule Trojan_Win32_Rhadamanthys_RDA_MTB{
	meta:
		description = "Trojan:Win32/Rhadamanthys.RDA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 54 24 18 89 56 48 03 6f 20 13 5f 24 89 6e 30 89 5e 34 8b 54 24 24 89 56 38 89 4e 3c 89 c1 83 c9 10 89 4e 1c a8 40 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}