
rule Trojan_BAT_Filecoder_PTBG_MTB{
	meta:
		description = "Trojan:BAT/Filecoder.PTBG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_03_0 = {6f 20 00 00 0a 13 0b 11 08 08 16 08 8e 69 6f 21 00 00 0a 11 08 6f 22 00 00 0a 09 11 0b 28 90 01 01 00 00 2b 28 90 01 01 00 00 2b 0d 09 11 07 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}