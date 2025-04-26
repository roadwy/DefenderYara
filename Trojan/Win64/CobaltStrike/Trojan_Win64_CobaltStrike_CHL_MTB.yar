
rule Trojan_Win64_CobaltStrike_CHL_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.CHL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {4d 63 ce 4c 3b 0b 73 0b 0f b6 d4 41 ff c6 42 88 54 0d 00 4d 63 ce 4c 3b 0b 73 08 42 88 44 0d 00 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}