
rule Trojan_Win64_TrueBot_SB_MTB{
	meta:
		description = "Trojan:Win64/TrueBot.SB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_03_0 = {41 fe c1 4c 8d 04 24 41 0f b6 c1 48 8d 0c 24 4c 03 c0 4d 8d 52 90 01 01 41 0f b6 10 44 02 da 90 00 } //1
		$a_03_1 = {41 0f b6 c3 48 03 c8 0f b6 01 41 88 00 88 11 41 0f b6 08 48 03 ca 0f b6 c1 0f b6 0c 04 41 30 4a 90 01 01 48 83 eb 90 01 01 75 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=1
 
}