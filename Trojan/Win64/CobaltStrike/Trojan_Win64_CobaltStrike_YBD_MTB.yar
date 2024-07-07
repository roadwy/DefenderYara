
rule Trojan_Win64_CobaltStrike_YBD_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.YBD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {48 8b c2 48 8d 49 01 83 e0 03 48 ff c2 0f b6 84 05 c8 01 00 00 32 84 39 a5 41 00 00 88 44 0c 27 49 83 e8 01 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}