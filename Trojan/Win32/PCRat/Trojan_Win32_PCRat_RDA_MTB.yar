
rule Trojan_Win32_PCRat_RDA_MTB{
	meta:
		description = "Trojan:Win32/PCRat.RDA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {66 89 44 24 12 8b 47 0c 6a 10 8b 08 8d 44 24 14 50 8b 11 8b 4e 08 51 89 54 24 20 ff 15 a0 20 40 00 83 f8 ff } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}