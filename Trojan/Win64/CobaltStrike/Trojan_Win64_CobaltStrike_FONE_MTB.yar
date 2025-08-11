
rule Trojan_Win64_CobaltStrike_FONE_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.FONE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {48 98 0f b6 44 05 90 88 85 96 00 00 00 48 8b 95 c0 00 00 00 48 8b 85 98 00 00 00 48 01 d0 0f b6 00 48 8b 8d c8 00 00 00 48 8b 95 98 00 00 00 48 01 ca 32 85 96 00 00 00 88 02 48 83 85 98 00 00 00 01 48 8b 85 98 00 00 00 48 3b 85 d0 00 00 00 0f 82 01 ff ff ff } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}