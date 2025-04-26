
rule Trojan_Win64_CobaltStrike_PS_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.PS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {48 8b c1 0f b6 00 83 f0 ?? 48 63 4c 24 ?? 48 6b c9 ?? 48 8d 54 24 ?? 48 03 d1 48 8b ca 88 01 eb } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}