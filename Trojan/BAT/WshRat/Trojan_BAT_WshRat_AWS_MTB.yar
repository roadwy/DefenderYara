
rule Trojan_BAT_WshRat_AWS_MTB{
	meta:
		description = "Trojan:BAT/WshRat.AWS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 02 00 "
		
	strings :
		$a_03_0 = {0a 2b 52 06 6f 90 01 01 00 00 0a 74 90 01 01 00 00 01 0b 7e 90 01 01 00 00 04 07 6f 90 01 01 01 00 0a 6f 90 01 01 01 00 0a 0c 08 2c 19 7e 90 01 01 00 00 04 07 6f 90 00 } //01 00 
		$a_01_1 = {57 00 53 00 48 00 52 00 61 00 74 00 2e 00 65 00 78 00 65 00 } //00 00  WSHRat.exe
	condition:
		any of ($a_*)
 
}