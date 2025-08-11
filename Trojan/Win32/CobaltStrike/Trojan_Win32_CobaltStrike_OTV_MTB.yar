
rule Trojan_Win32_CobaltStrike_OTV_MTB{
	meta:
		description = "Trojan:Win32/CobaltStrike.OTV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {49 81 c9 00 ff ff ff 41 8b 85 ?? ?? ff ff 8b 95 f4 fd ff ff 0f b6 8c 0d ?? ?? ff ff 30 0c 10 40 89 85 f8 fd ff ff 3b c7 7c 82 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}