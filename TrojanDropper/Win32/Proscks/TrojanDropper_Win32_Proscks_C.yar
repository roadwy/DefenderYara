
rule TrojanDropper_Win32_Proscks_C{
	meta:
		description = "TrojanDropper:Win32/Proscks.C,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {68 04 01 00 00 68 90 01 03 00 e8 90 01 02 ff ff e8 01 02 03 ff 15 90 01 03 00 68 90 01 03 00 e8 90 01 02 ff ff e8 01 02 03 ff 15 90 01 02 40 00 e8 90 01 02 ff ff e8 01 02 03 e8 0c 00 00 00 74 61 73 6b 6d 67 72 2e 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}