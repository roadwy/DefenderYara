
rule Trojan_Win64_CobaltStrike_CCFD_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.CCFD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {48 8b 0b 4c 8d 44 24 ?? 4c 63 cf 33 d2 4c 03 cd ff 15 ?? ?? ?? ?? 85 c0 78 ?? 83 c7 ?? ff c6 48 83 c3 ?? 49 3b de 7c } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}