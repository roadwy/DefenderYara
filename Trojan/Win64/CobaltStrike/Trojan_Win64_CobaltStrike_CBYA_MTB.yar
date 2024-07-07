
rule Trojan_Win64_CobaltStrike_CBYA_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.CBYA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f be 34 17 01 ce 89 f1 c1 e9 90 01 01 31 f1 0f be 74 17 01 01 ce 89 f1 c1 e9 90 01 01 31 f1 0f be 74 17 02 01 ce 89 f1 c1 e9 90 01 01 31 f1 0f be 74 17 03 01 ce 89 f1 c1 e9 90 01 01 31 f1 48 83 c2 90 01 01 49 39 d0 75 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}