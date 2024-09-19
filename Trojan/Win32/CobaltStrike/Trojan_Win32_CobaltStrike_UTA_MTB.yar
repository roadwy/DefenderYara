
rule Trojan_Win32_CobaltStrike_UTA_MTB{
	meta:
		description = "Trojan:Win32/CobaltStrike.UTA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {89 4b 08 89 53 04 89 5c 24 0c 89 44 24 08 89 4c 24 04 89 14 24 ff 15 14 81 40 00 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}