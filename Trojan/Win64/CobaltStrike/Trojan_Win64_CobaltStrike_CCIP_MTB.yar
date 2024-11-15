
rule Trojan_Win64_CobaltStrike_CCIP_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.CCIP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {88 18 48 8b 45 f0 48 89 c2 48 8b 4d 20 e8 ?? ?? ?? ?? 0f b6 10 8b 4d fc 31 ca 88 10 81 45 fc ?? ?? ?? ?? 48 83 45 f0 01 e9 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}