
rule Trojan_BAT_RemcosRAT_NRQ_MTB{
	meta:
		description = "Trojan:BAT/RemcosRAT.NRQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 05 00 "
		
	strings :
		$a_03_0 = {20 00 01 00 00 14 14 17 8d 90 01 02 00 01 25 16 08 a2 90 00 } //01 00 
		$a_01_1 = {4c 6b 58 45 2e 65 78 65 } //00 00  LkXE.exe
	condition:
		any of ($a_*)
 
}