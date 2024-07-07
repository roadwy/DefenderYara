
rule Trojan_Win64_IcedID_MAX_MTB{
	meta:
		description = "Trojan:Win64/IcedID.MAX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {48 89 84 24 80 00 00 00 48 8b 84 24 80 00 00 00 e9 90 01 04 33 c0 e9 90 01 04 8b 84 24 94 00 00 00 e9 90 01 04 48 8b 8c 24 48 01 00 00 48 3b c8 74 90 01 01 eb 90 01 01 48 8b 84 24 30 01 00 00 48 89 84 24 58 01 00 00 e9 90 01 04 41 8a 04 00 88 04 0a e9 90 00 } //5
		$a_01_1 = {79 67 61 67 6b 61 73 6a 66 68 75 61 73 68 66 6a 6b 61 73 6a 61 73 68 } //1 ygagkasjfhuashfjkasjash
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}