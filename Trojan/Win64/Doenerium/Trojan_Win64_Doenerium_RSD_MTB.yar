
rule Trojan_Win64_Doenerium_RSD_MTB{
	meta:
		description = "Trojan:Win64/Doenerium.RSD!MTB,SIGNATURE_TYPE_PEHSTR,09 00 09 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {54 52 59 5f 54 4f 5f 44 45 43 52 59 50 54 5f 4d 45 5f 58 44 } //01 00  TRY_TO_DECRYPT_ME_XD
		$a_01_1 = {42 61 73 65 36 34 44 65 63 6f 64 65 } //01 00  Base64Decode
		$a_01_2 = {49 6e 6a 65 63 74 } //01 00  Inject
		$a_01_3 = {53 63 72 65 65 6e 53 68 6f 74 } //05 00  ScreenShot
		$a_01_4 = {6f 6e 6c 69 6e 65 2d 62 69 6c 65 74 73 2e 6e 65 74 2f 73 74 65 61 6c 65 72 } //00 00  online-bilets.net/stealer
	condition:
		any of ($a_*)
 
}