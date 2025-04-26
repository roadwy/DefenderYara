
rule TrojanDownloader_O97M_Remcos_JW_MTB{
	meta:
		description = "TrojanDownloader:O97M/Remcos.JW!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {3a 2f 2f 6c 6f 66 74 2e 6c 6f 6e 64 6f 6e 2f 76 65 6e 64 6f 72 2f 70 68 70 75 6e 69 74 2f 70 68 70 75 6e 69 74 2f 73 72 63 2f 55 74 69 6c 2f 50 48 50 2f 6f 64 65 72 2e 65 78 65 } //1 ://loft.london/vendor/phpunit/phpunit/src/Util/PHP/oder.exe
	condition:
		((#a_01_0  & 1)*1) >=1
 
}