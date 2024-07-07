
rule Trojan_Win64_Dacic_ADZ_MTB{
	meta:
		description = "Trojan:Win64/Dacic.ADZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {33 d2 41 b8 00 80 00 00 49 8b cc ff 15 90 01 04 8b 55 df 33 c9 44 8d 49 04 41 b8 00 30 00 00 ff 15 90 01 04 4c 8b e0 4c 8d 4d df 44 8b 45 df 48 8b d0 b9 0b 00 00 00 ff 15 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}