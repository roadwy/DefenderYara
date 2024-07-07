
rule Trojan_Win64_CobaltStrike_TJ_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.TJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {48 89 c8 31 d2 49 f7 f6 48 39 cf 74 1f 48 6b c0 90 01 01 48 01 f0 48 8d 59 90 01 01 8a 14 08 32 54 0d 90 01 01 4c 89 f9 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}