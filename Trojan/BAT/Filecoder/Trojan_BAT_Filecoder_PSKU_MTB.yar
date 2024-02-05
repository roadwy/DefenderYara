
rule Trojan_BAT_Filecoder_PSKU_MTB{
	meta:
		description = "Trojan:BAT/Filecoder.PSKU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_03_0 = {72 65 00 00 70 28 1d 00 00 06 0b 28 90 01 03 0a 07 6f 90 01 03 0a 72 a5 00 00 70 7e 90 01 03 0a 6f 90 01 03 0a 28 90 01 03 0a 0c de 0d 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}