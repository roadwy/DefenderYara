
rule Trojan_Win32_Truebot_SB{
	meta:
		description = "Trojan:Win32/Truebot.SB,SIGNATURE_TYPE_CMDHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {72 00 75 00 6e 00 64 00 6c 00 6c 00 33 00 32 00 2e 00 65 00 78 00 65 00 20 00 90 02 ff 2c 00 43 00 68 00 6b 00 64 00 73 00 6b 00 45 00 78 00 73 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}