
rule Trojan_Win64_BlackWidow_BJ_MTB{
	meta:
		description = "Trojan:Win64/BlackWidow.BJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_01_0 = {49 f7 f2 48 83 c2 03 45 8a 5c 15 } //1
		$a_01_1 = {44 30 1c 0f } //1 い༜
		$a_01_2 = {37 3c 4a 59 78 6a 21 4b } //3 7<JYxj!K
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*3) >=5
 
}