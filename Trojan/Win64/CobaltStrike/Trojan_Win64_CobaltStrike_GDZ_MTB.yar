
rule Trojan_Win64_CobaltStrike_GDZ_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.GDZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_03_0 = {33 c9 48 63 f8 48 8b d7 41 b8 00 30 00 00 48 03 d2 44 8d 49 ?? ff 15 } //5
		$a_03_1 = {8b 45 a7 33 c8 89 4d a7 b9 ?? ?? ?? ?? 8b 45 a7 89 75 a7 } //5
	condition:
		((#a_03_0  & 1)*5+(#a_03_1  & 1)*5) >=10
 
}