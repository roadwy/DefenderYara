
rule Trojan_Win64_Bumblebee_NI_MTB{
	meta:
		description = "Trojan:Win64/Bumblebee.NI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {41 33 c6 0f af 05 90 01 04 3b f8 74 90 01 01 8b 8b 90 01 04 23 4b 90 01 01 41 03 cc ff 15 90 01 04 8b 0d 90 01 04 8b 83 90 01 04 8b 15 90 01 04 35 90 01 04 0f af c8 89 0d 90 01 04 48 8b 0d 90 01 04 41 83 c7 90 01 01 8b c2 2b 83 90 01 04 0f af 81 90 01 04 44 3b f8 76 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}