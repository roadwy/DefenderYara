
rule Trojan_Win64_Bumblebee_MUR_MTB{
	meta:
		description = "Trojan:Win64/Bumblebee.MUR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {4d 8b f2 49 8d 1c 02 4c 8b 94 24 90 01 04 4d 2b d6 4c 89 94 24 90 01 04 48 2b f8 41 8a 0c 1a 2a 8c 24 90 01 04 32 8c 24 90 01 04 49 8b 41 90 01 01 88 0c 03 83 fe 08 0f 84 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}