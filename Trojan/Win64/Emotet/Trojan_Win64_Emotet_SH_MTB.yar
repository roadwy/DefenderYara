
rule Trojan_Win64_Emotet_SH_MTB{
	meta:
		description = "Trojan:Win64/Emotet.SH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_01_0 = {48 63 d1 0f b6 0c 02 41 32 0c 36 88 0e } //1
		$a_01_1 = {41 b9 00 30 00 00 48 8b c8 89 7c 24 28 4c 8b c5 89 5c 24 20 33 d2 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=1
 
}