
rule Trojan_Win64_Dacic_ADC_MTB{
	meta:
		description = "Trojan:Win64/Dacic.ADC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {4c 03 c0 66 66 0f 1f 84 00 90 01 04 b8 93 24 49 92 4d 8d 40 01 f7 e9 03 d1 c1 fa 05 8b c2 c1 e8 1f 03 d0 0f be c2 6b d0 38 0f b6 c1 ff c1 2a c2 04 36 41 30 40 ff 83 f9 0c 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}