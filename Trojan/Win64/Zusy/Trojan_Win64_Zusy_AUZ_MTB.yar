
rule Trojan_Win64_Zusy_AUZ_MTB{
	meta:
		description = "Trojan:Win64/Zusy.AUZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {48 8d 15 66 af 03 00 48 8b cb 48 89 05 14 30 14 00 ff 15 90 01 04 48 8d 15 67 af 03 00 48 8b cb 48 89 05 05 30 14 00 ff 15 90 01 04 48 8d 15 70 af 03 00 48 8b cb 48 89 05 f6 2f 14 00 ff 15 90 01 04 48 8d 15 71 af 03 00 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}