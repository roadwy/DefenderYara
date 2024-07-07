
rule Trojan_Win64_CobaltStrike_LKK_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.LKK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {53 64 4a 46 6c 73 6b 64 6a 66 } //1 SdJFlskdjf
		$a_03_1 = {ba 0c 00 00 f0 00 00 00 00 00 00 90 01 02 0b 00 00 10 00 00 00 00 00 80 01 90 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}