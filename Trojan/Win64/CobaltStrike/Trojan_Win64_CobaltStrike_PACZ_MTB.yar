
rule Trojan_Win64_CobaltStrike_PACZ_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.PACZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {48 8b 55 10 48 8b 45 f8 48 01 d0 0f b6 00 89 c1 48 8b 45 f8 ba ?? ?? ?? ?? 48 f7 75 f0 48 8b 45 20 48 01 d0 0f b6 00 31 c1 48 8b 55 10 48 8b 45 f8 48 01 d0 89 ca 88 10 48 83 45 f8 01 48 8b 45 f8 48 3b 45 18 72 b9 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}