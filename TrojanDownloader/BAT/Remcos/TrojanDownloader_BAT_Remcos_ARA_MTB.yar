
rule TrojanDownloader_BAT_Remcos_ARA_MTB{
	meta:
		description = "TrojanDownloader:BAT/Remcos.ARA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_01_0 = {72 0d 00 00 70 28 05 00 00 06 0a 28 05 00 00 0a 06 6f 06 00 00 0a 28 07 00 00 0a 28 03 00 00 06 0b dd 03 00 00 00 26 de d6 } //00 00 
	condition:
		any of ($a_*)
 
}