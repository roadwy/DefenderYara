
rule Trojan_BAT_Marsilia_NM_MTB{
	meta:
		description = "Trojan:BAT/Marsilia.NM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 05 00 "
		
	strings :
		$a_03_0 = {07 08 6f 55 00 00 0a 08 16 28 90 01 02 00 0a 0d 06 72 90 01 02 00 70 09 72 90 01 02 00 70 6f 90 01 02 00 0a 5e 6f 90 01 02 00 0a 6f 90 01 02 00 0a 26 02 25 17 59 10 00 16 30 cb 90 00 } //01 00 
		$a_01_1 = {63 69 61 6f 2d 64 65 63 72 79 70 74 65 72 2e 65 78 65 } //00 00  ciao-decrypter.exe
	condition:
		any of ($a_*)
 
}