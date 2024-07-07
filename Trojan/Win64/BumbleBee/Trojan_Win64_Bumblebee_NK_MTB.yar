
rule Trojan_Win64_Bumblebee_NK_MTB{
	meta:
		description = "Trojan:Win64/Bumblebee.NK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {41 8a 44 8d 90 01 01 32 04 cd 90 01 04 0f b6 c8 41 90 01 04 0f af c1 41 90 01 03 8b 05 90 01 04 0f b7 15 90 01 04 83 c0 90 01 01 48 63 c8 41 90 01 04 66 89 04 4b 8b 05 90 01 04 44 3b c8 7c 90 01 01 4c 8b 05 90 01 04 e9 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}