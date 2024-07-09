
rule Trojan_Win64_CobaltStrike_YYY_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.YYY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {4d 01 d1 49 bb db 28 b4 a0 d1 7e 03 e7 4d 31 cb 48 89 c7 4c 89 c8 49 89 d4 49 f7 e3 4d 89 88 ?? ?? ?? ?? 44 8b 05 44 75 30 00 48 31 d0 ?? 45 85 c0 0f 84 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}