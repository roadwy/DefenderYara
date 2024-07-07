
rule Trojan_Win64_CobaltStrike_TBC_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.TBC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {48 98 48 8d 0d 97 83 11 00 0f b6 04 01 88 45 64 48 8b 85 90 01 00 00 0f be 00 0f b6 4d 64 33 c1 88 85 84 00 00 00 48 8b 85 90 01 00 00 0f b6 8d 84 00 00 00 88 08 48 8b 85 90 01 00 00 48 ff c0 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}