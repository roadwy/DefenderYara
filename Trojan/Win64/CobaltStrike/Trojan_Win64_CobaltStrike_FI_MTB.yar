
rule Trojan_Win64_CobaltStrike_FI_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.FI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f b6 08 48 8b 45 ?? ba ?? ?? ?? ?? 48 f7 75 ?? 48 8b 45 ?? 48 01 d0 0f b6 10 4c 8b 45 ?? 48 8b 45 ?? 4c 01 c0 31 ca 88 10 48 83 45 ?? ?? eb } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}