
rule Trojan_Win64_Bumblebee_FB_MTB{
	meta:
		description = "Trojan:Win64/Bumblebee.FB!MTB,SIGNATURE_TYPE_PEHSTR,08 00 08 00 04 00 00 "
		
	strings :
		$a_01_0 = {4c 6f 4f 5a 7a 34 36 50 78 } //1 LoOZz46Px
		$a_01_1 = {54 66 4c 58 76 31 32 6b } //1 TfLXv12k
		$a_01_2 = {56 52 49 5a 53 36 70 } //1 VRIZS6p
		$a_01_3 = {63 6d 66 67 75 74 69 6c } //5 cmfgutil
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*5) >=8
 
}