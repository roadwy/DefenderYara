
rule Trojan_Win64_CobaltStrike_BA_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.BA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {48 89 c2 83 e2 03 8a 54 15 00 32 14 07 88 14 03 48 ff c0 eb } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}