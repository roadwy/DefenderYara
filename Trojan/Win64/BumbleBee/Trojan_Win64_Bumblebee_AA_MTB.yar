
rule Trojan_Win64_Bumblebee_AA_MTB{
	meta:
		description = "Trojan:Win64/Bumblebee.AA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f af c2 41 8b d0 c1 ea 08 89 45 90 01 01 48 8b 85 90 01 04 88 14 01 ff 85 90 01 04 48 63 8d 90 01 04 48 8b 85 90 01 04 44 88 04 01 ff 85 90 01 04 49 81 f9 90 01 04 90 13 8b 95 90 01 04 8d 42 90 01 01 31 85 90 01 04 8b 45 90 01 01 2d 90 01 04 01 85 90 01 04 8b 45 90 01 01 09 85 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}