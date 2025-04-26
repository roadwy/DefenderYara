
rule Trojan_Win64_CobaltStrike_OFK_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.OFK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f b6 c8 44 02 d9 44 02 df 41 0f b6 cb 49 83 c6 05 41 0f b6 44 8d 08 41 30 46 fe 41 8b 44 8d 08 41 31 44 95 ?? 41 8b 44 ad 08 41 8d 0c 00 43 31 4c 95 08 49 ff cf 0f 85 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}