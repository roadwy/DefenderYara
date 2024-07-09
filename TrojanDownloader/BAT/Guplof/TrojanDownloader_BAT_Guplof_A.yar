
rule TrojanDownloader_BAT_Guplof_A{
	meta:
		description = "TrojanDownloader:BAT/Guplof.A,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {00 2e 00 67 00 75 00 6c 00 66 00 75 00 70 00 2e 00 63 00 6f 00 6d 00 2f 00 ?? 00 ?? 00 ?? 00 ?? 00 ?? 00 2e 00 6a 00 70 00 67 00 00 09 2e 00 65 00 78 00 65 00 00 09 2e 00 6a 00 70 00 67 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}