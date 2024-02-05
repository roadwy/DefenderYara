
rule TrojanDownloader_BAT_Dae_A_MTB{
	meta:
		description = "TrojanDownloader:BAT/Dae.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {28 01 00 00 06 26 07 14 28 02 00 00 06 26 dd 03 00 00 00 } //00 00 
	condition:
		any of ($a_*)
 
}