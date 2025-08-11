
rule Trojan_Win64_Bumblebee_AHB_MTB{
	meta:
		description = "Trojan:Win64/Bumblebee.AHB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 01 00 00 "
		
	strings :
		$a_03_0 = {89 45 a4 66 c7 45 a0 02 00 b9 50 00 00 00 48 8b ?? ?? ?? ?? 00 ff d0 66 89 45 a2 48 8d 55 a0 48 8b 85 58 01 00 00 41 b8 10 00 00 00 48 89 c1 48 8b ?? ?? ?? ?? 00 ff d0 } //3
	condition:
		((#a_03_0  & 1)*3) >=3
 
}