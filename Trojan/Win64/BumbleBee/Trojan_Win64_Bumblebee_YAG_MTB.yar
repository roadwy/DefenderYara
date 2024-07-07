
rule Trojan_Win64_Bumblebee_YAG_MTB{
	meta:
		description = "Trojan:Win64/Bumblebee.YAG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {41 8b d3 48 8b 8d 90 01 04 4c 8b 85 90 01 04 41 69 80 90 01 08 48 31 8d 90 01 04 44 03 d0 48 8d 41 01 48 89 85 90 01 04 48 8b 85 90 01 04 48 8b 88 90 01 04 48 81 f1 90 01 04 48 29 8d 90 01 04 41 8b ca 41 8a 80 90 01 04 d3 ea 34 42 48 63 8d 90 01 04 22 d0 48 8b 45 90 01 01 88 14 01 90 00 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}