
rule Trojan_Win64_CobaltStrike_CRIO_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.CRIO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 45 f4 3b 45 e4 7d 4a 4c 8b 45 f8 8b 45 f4 48 98 48 8d 14 c5 00 00 00 00 48 8d ?? ?? ?? ?? ?? 48 01 c2 8b 45 f4 48 98 48 8d 0c c5 00 00 00 00 48 8d ?? ?? ?? ?? ?? 48 8b 04 01 48 89 c1 48 8b 05 3c 6c 0f 00 ff d0 48 83 45 f8 06 83 45 f4 01 eb } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}