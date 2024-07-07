
rule Trojan_Win64_Dridex_G_MTB{
	meta:
		description = "Trojan:Win64/Dridex.G!MTB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {53 48 83 ec 70 48 8d 6c 24 70 b8 dd 97 00 00 41 89 c1 b8 21 79 00 00 48 c7 45 f8 58 52 00 00 c7 45 f4 5e } //1
		$a_01_1 = {eb 88 a7 e4 12 3c b8 89 bb ce 8a 19 90 8a cf aa bc 8a d8 7e da 0a cb b1 cf e7 9b } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}