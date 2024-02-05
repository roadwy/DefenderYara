
rule Trojan_Win32_Trickbot_CRYP{
	meta:
		description = "Trojan:Win32/Trickbot.CRYP,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {68 00 10 00 00 90 02 02 59 90 02 02 52 e2 fd 90 02 03 8b ec 90 02 02 05 90 01 04 68 f1 ff 00 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}