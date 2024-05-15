
rule Trojan_BAT_Quasar_ASER_MTB{
	meta:
		description = "Trojan:BAT/Quasar.ASER!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 02 00 "
		
	strings :
		$a_01_0 = {91 08 61 d2 9c 09 17 5f 17 33 07 11 0a 11 04 58 13 0a 08 1b 64 08 1f 1b 62 60 1d 5a 0c 09 17 64 09 } //02 00 
		$a_01_1 = {43 00 3a 00 5c 00 53 00 45 00 4c 00 46 00 2e 00 45 00 58 00 45 00 } //00 00  C:\SELF.EXE
	condition:
		any of ($a_*)
 
}