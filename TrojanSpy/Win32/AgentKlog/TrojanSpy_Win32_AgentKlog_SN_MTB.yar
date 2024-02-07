
rule TrojanSpy_Win32_AgentKlog_SN_MTB{
	meta:
		description = "TrojanSpy:Win32/AgentKlog.SN!MTB,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {77 00 61 00 72 00 6b 00 61 00 5c 00 6b 00 75 00 6c 00 5c 00 32 00 30 00 31 00 2d 00 73 00 6f 00 6c 00 69 00 74 00 61 00 69 00 72 00 65 00 5c 00 53 00 6f 00 6c 00 69 00 74 00 61 00 69 00 72 00 65 00 2e 00 76 00 62 00 70 00 } //01 00  warka\kul\201-solitaire\Solitaire.vbp
		$a_01_1 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 68 00 65 00 6d 00 31 00 2e 00 70 00 61 00 73 00 73 00 61 00 67 00 65 00 6e 00 2e 00 73 00 65 00 2f 00 66 00 79 00 6c 00 6b 00 65 00 2f 00 } //01 00  http://hem1.passagen.se/fylke/
		$a_01_2 = {61 00 6e 00 64 00 65 00 72 00 73 00 2e 00 66 00 72 00 61 00 6e 00 73 00 73 00 6f 00 6e 00 40 00 68 00 6f 00 6d 00 65 00 2e 00 73 00 65 00 } //00 00  anders.fransson@home.se
	condition:
		any of ($a_*)
 
}