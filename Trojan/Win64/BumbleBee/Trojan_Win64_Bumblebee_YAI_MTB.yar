
rule Trojan_Win64_Bumblebee_YAI_MTB{
	meta:
		description = "Trojan:Win64/Bumblebee.YAI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {85 c9 74 03 41 d3 c8 49 63 82 4c 05 00 00 44 01 04 82 41 b8 ?? ?? ?? ?? 4d 8b 8a } //1
		$a_03_1 = {41 8b 0c 80 41 31 0c 90 90 41 8b 8a 7c 05 00 00 81 e1 1f 00 00 80 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}