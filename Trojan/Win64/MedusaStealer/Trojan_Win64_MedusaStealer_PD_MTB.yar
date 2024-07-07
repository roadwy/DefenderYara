
rule Trojan_Win64_MedusaStealer_PD_MTB{
	meta:
		description = "Trojan:Win64/MedusaStealer.PD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {46 8a 04 02 41 b9 15 00 00 00 31 d2 41 f7 f1 8b 44 24 04 41 89 d1 48 8b 54 24 08 4d 63 c9 46 32 04 0a 48 63 d0 44 88 04 11 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}