
rule Trojan_BAT_Dapato_AD_MTB{
	meta:
		description = "Trojan:BAT/Dapato.AD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 02 00 "
		
	strings :
		$a_03_0 = {0a 2c 13 07 2c 04 16 0b 2b 0c 72 f5 02 00 70 28 90 01 03 0a 16 2a 09 17 58 0d 09 08 8e 69 32 d3 72 1d 03 00 70 90 00 } //01 00 
		$a_01_1 = {43 00 61 00 6c 00 6c 00 43 00 6f 00 72 00 65 00 49 00 6e 00 73 00 74 00 61 00 6c 00 6c 00 2e 00 65 00 78 00 65 00 } //01 00  CallCoreInstall.exe
		$a_01_2 = {61 00 6c 00 73 00 6f 00 70 00 77 00 6e 00 72 00 75 00 6e 00 } //00 00  alsopwnrun
	condition:
		any of ($a_*)
 
}