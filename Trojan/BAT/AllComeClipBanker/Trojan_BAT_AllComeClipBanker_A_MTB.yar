
rule Trojan_BAT_AllComeClipBanker_A_MTB{
	meta:
		description = "Trojan:BAT/AllComeClipBanker.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {4a 00 48 00 46 00 53 00 41 00 53 00 4e 00 20 00 4b 00 41 00 53 00 46 00 48 00 } //1 JHFSASN KASFH
		$a_01_1 = {49 00 53 00 44 00 46 00 4a 00 38 00 59 00 20 00 49 00 4f 00 41 00 4a 00 46 00 } //1 ISDFJ8Y IOAJF
		$a_01_2 = {44 00 46 00 53 00 53 00 46 00 4a 00 49 00 57 00 20 00 41 00 57 00 57 00 52 00 } //1 DFSSFJIW AWWR
		$a_01_3 = {54 6f 49 6e 74 65 67 65 72 } //1 ToInteger
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}