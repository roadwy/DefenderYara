
rule Trojan_Win64_CobaltStrike_CCEI_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.CCEI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {ba 09 0e 04 00 44 8d 49 40 41 b8 00 10 00 00 ff 15 ?? ?? ?? ?? 41 b8 09 0e 04 00 48 8d 94 24 ?? ?? ?? ?? 48 8b c8 48 8b d8 e8 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}