
rule Trojan_Win32_CobaltStrike_CCBG_MTB{
	meta:
		description = "Trojan:Win32/CobaltStrike.CCBG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {68 24 97 a9 3e 68 19 db 6f 3e 68 19 db 6f 3e 68 19 db 6f 3e 68 61 70 a5 3e e8 90 01 04 83 c4 14 33 c0 3b ec 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}