
rule Trojan_Win64_Redline_YT_MTB{
	meta:
		description = "Trojan:Win64/Redline.YT!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {48 8b 4e 10 41 0a c4 41 0f bc c1 66 0f ab f8 41 0f b6 46 0f 66 44 3b dd 30 04 19 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}