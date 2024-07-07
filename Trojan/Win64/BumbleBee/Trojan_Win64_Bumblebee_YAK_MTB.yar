
rule Trojan_Win64_Bumblebee_YAK_MTB{
	meta:
		description = "Trojan:Win64/Bumblebee.YAK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {89 cf 8b 7d ff 4d 89 f4 4d 89 fa 48 33 45 ee bf 90 01 04 4c 89 2d f9 92 13 00 8b 3d e2 96 13 00 8b 55 fe 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}