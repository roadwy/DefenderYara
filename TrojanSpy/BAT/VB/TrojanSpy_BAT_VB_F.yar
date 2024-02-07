
rule TrojanSpy_BAT_VB_F{
	meta:
		description = "TrojanSpy:BAT/VB.F,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 03 00 00 04 00 "
		
	strings :
		$a_00_0 = {40 00 49 00 6e 00 6a 00 65 00 63 00 74 00 69 00 6f 00 6e 00 40 00 } //04 00  @Injection@
		$a_01_1 = {41 6e 74 69 4b 65 79 73 63 72 61 6d 62 6c 65 72 } //03 00  AntiKeyscrambler
		$a_01_2 = {4b 42 44 4c 4c 48 4f 4f 4b 53 54 52 55 43 54 } //00 00  KBDLLHOOKSTRUCT
	condition:
		any of ($a_*)
 
}