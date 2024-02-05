
rule Trojan_Win32_CobaltStrike_UZ_MTB{
	meta:
		description = "Trojan:Win32/CobaltStrike.UZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {03 ca 09 88 90 01 04 8b 88 90 01 04 2b 88 90 01 04 31 48 90 01 01 8b 88 90 01 04 01 48 90 01 01 8d 8a 90 01 04 01 88 90 01 04 8b 88 90 01 04 81 e9 90 01 04 01 48 90 01 01 8b 48 90 01 01 2b 88 90 01 04 81 e9 90 01 04 01 48 90 01 01 81 ff 90 01 04 7c 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}