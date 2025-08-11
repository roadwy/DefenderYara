
rule Trojan_BAT_DCRat_GTD_MTB{
	meta:
		description = "Trojan:BAT/DCRat.GTD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 "
		
	strings :
		$a_03_0 = {04 06 08 16 6f ?? 00 00 0a 0d 12 03 28 ?? 00 00 0a 6f ?? 00 00 0a 08 17 d6 0c 08 07 31 de } //10
		$a_01_1 = {4c 00 30 00 35 00 78 00 53 00 30 00 4e 00 45 00 56 00 48 00 42 00 6e 00 4c 00 6e 00 42 00 75 00 5a 00 77 00 } //1 L05xS0NEVHBnLnBuZw
	condition:
		((#a_03_0  & 1)*10+(#a_01_1  & 1)*1) >=11
 
}