
rule Trojan_Win32_Facbot_A{
	meta:
		description = "Trojan:Win32/Facbot.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {50 72 6f 66 69 6c 65 56 69 73 69 74 6f 72 2e 70 6c 75 67 69 6e 2e 66 6b 6c 69 62 69 69 6c 68 6c 70 6a 69 6f 62 68 66 62 63 68 66 6e 64 63 6f 62 65 67 6e 6f 68 68 2e } //01 00  ProfileVisitor.plugin.fklibiilhlpjiobhfbchfndcobegnohh.
		$a_01_1 = {2a 3a 2f 2f 2a 2e 66 61 63 65 62 6f 6f 6b 2e 63 6f 6d 2f 22 2c 20 22 74 61 62 73 22 2c 20 22 63 6f 6f 6b 69 65 73 22 2c 20 22 6e 6f 74 69 66 69 63 61 74 69 6f 6e 73 22 2c } //00 00  *://*.facebook.com/", "tabs", "cookies", "notifications",
	condition:
		any of ($a_*)
 
}