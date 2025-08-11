
rule Trojan_Win64_CobaltStrike_FTW_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.FTW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {48 98 0f b6 44 05 c0 88 85 fe 08 00 00 48 8d 95 d0 00 00 00 48 8b 85 28 09 00 00 48 01 d0 0f b6 00 48 8b 8d 08 09 00 00 48 8b 95 28 09 00 00 48 01 ca 32 85 fe 08 00 00 88 02 48 83 85 28 09 00 00 01 48 8b 85 28 09 00 00 48 3b 85 18 09 00 00 0f 82 01 ff ff ff } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}