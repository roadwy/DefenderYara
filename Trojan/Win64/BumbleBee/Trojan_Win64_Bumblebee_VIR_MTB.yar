
rule Trojan_Win64_Bumblebee_VIR_MTB{
	meta:
		description = "Trojan:Win64/Bumblebee.VIR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {4d 8d 1c 08 4d 2b e8 4c 89 1c 24 49 8b f0 4c 89 ac 24 90 01 04 44 0f b7 44 24 90 01 01 48 2b d9 43 8a 0c 2b 2a 8c 24 90 01 04 32 8c 24 90 01 04 49 8b 41 90 01 01 41 88 0c 03 83 ff 08 0f 84 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}