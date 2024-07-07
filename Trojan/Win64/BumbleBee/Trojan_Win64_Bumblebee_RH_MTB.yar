
rule Trojan_Win64_Bumblebee_RH_MTB{
	meta:
		description = "Trojan:Win64/Bumblebee.RH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {49 0b ca 48 0f af c1 48 89 42 90 01 01 49 63 96 90 01 04 49 8b 0e 49 8b 46 90 01 01 8a 14 0a 41 32 14 00 49 8b 46 90 01 01 41 88 14 00 49 ff c0 49 8b 86 90 01 04 49 8b 8e 90 01 04 49 0b cb 48 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}