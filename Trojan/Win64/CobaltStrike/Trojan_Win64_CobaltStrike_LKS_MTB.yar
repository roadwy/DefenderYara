
rule Trojan_Win64_CobaltStrike_LKS_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.LKS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_01_0 = {41 32 10 88 11 41 32 10 41 88 10 32 11 88 11 eb } //1
		$a_01_1 = {41 0f b6 54 0d 00 41 8a 0c 0e 88 0c 17 48 63 c8 ff c0 48 39 f1 72 e9 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=1
 
}