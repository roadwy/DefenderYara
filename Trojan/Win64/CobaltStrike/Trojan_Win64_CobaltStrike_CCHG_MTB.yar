
rule Trojan_Win64_CobaltStrike_CCHG_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.CCHG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 44 24 20 48 8b 4c 24 78 0f be 04 01 33 44 24 24 8b 4c 24 20 88 44 0c 2c 8b 4c 24 24 e8 ?? ?? ?? ?? 25 ff 00 00 00 89 44 24 24 eb } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}