
rule Trojan_Win64_CobaltStrike_MTV_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.MTV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {48 0f af c1 66 89 05 59 c1 19 00 8b 44 24 60 35 a5 00 00 00 48 98 48 89 84 24 ?? ?? ?? ?? 8b 05 ac e4 bf 00 48 89 05 c5 c1 19 00 0f b6 05 ?? ?? ?? ?? 0f be c0 2d 3d 9b ad 9d 89 44 24 70 0f be 44 24 43 0f b6 4c 24 40 0f b6 c9 2b c1 0f be 4c 24 43 2b c8 8b c1 88 44 24 43 e9 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}