
rule Trojan_Win64_Barys_NE_MTB{
	meta:
		description = "Trojan:Win64/Barys.NE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_03_0 = {4c 39 ca 74 0e 46 8a 54 0c 30 46 90 01 01 14 0f 49 ff c1 90 00 } //5
		$a_01_1 = {48 39 ca 74 0d 44 8a 04 08 45 30 04 0c 48 ff c1 eb ee } //5
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*5) >=10
 
}