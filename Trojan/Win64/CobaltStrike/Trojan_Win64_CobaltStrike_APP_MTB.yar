
rule Trojan_Win64_CobaltStrike_APP_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.APP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f b6 c8 44 02 d9 44 02 df 41 0f b6 cb 41 0f b6 44 8e 08 41 30 47 01 41 8b 44 8e ?? 41 31 44 96 ?? 41 8b 44 ae 08 41 8d 0c 00 43 31 4c 96 ?? 40 fe c5 40 0f b6 ed } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}