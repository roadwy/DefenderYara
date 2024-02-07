
rule TrojanDownloader_O97M_Emotet_SDPK_MTB{
	meta:
		description = "TrojanDownloader:O97M/Emotet.SDPK!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {2f 62 64 74 69 6e 2e 63 6f 6d 2f 63 61 63 68 65 2f 34 47 38 70 6c 2f } //01 00  /bdtin.com/cache/4G8pl/
		$a_01_1 = {2f 62 61 73 63 6f 79 73 6f 6e 69 64 6f 2e 63 6f 6d 2e 61 72 2f 63 67 69 2d 62 69 6e 2f 41 6d 55 55 50 68 57 4b 36 6f 54 4b 4c 7a 48 70 6c 37 7a 6d 2f } //01 00  /bascoysonido.com.ar/cgi-bin/AmUUPhWK6oTKLzHpl7zm/
		$a_01_2 = {2f 62 61 73 6e 65 74 62 64 2e 63 6f 6d 2f 63 6b 66 69 6e 64 65 72 2f 4b 30 61 2f } //00 00  /basnetbd.com/ckfinder/K0a/
	condition:
		any of ($a_*)
 
}