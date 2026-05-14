
rule Trojan_Win64_BruteRat_ABR_MTB{
	meta:
		description = "Trojan:Win64/BruteRat.ABR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {4c 89 e2 48 01 d9 e8 ?? ?? ?? ?? 41 89 c0 48 8d 46 01 45 85 c0 75 1c 8b 57 24 48 01 f6 8b 47 1c 48 01 de 0f b7 14 16 48 8d 14 93 8b 04 02 48 01 d8 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}