
rule TrojanDownloader_O97M_Masslogger_PM_MTB{
	meta:
		description = "TrojanDownloader:O97M/Masslogger.PM!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_00_0 = {43 61 6c 6c 20 53 68 65 6c 6c 24 28 22 72 45 47 73 76 52 33 32 } //01 00  Call Shell$("rEGsvR32
		$a_00_1 = {2d 69 3a 68 74 74 70 73 3a 2f 2f 76 69 61 2e 68 79 70 6f 74 68 65 73 2e 69 73 2f 62 6f 79 61 6d 61 2e 6d 65 64 79 61 6e 65 66 2e 63 6f 6d 2f 76 65 6e 64 6f 72 2f 70 68 70 75 6e 69 74 2f 70 68 70 75 6e 69 74 2f 73 72 63 2f 55 74 69 6c 2f 4c 6f 67 2f 42 63 2e 77 73 63 } //01 00  -i:https://via.hypothes.is/boyama.medyanef.com/vendor/phpunit/phpunit/src/Util/Log/Bc.wsc
		$a_00_2 = {53 43 72 6f 42 4a 2e 44 6c 6c } //01 00  SCroBJ.Dll
		$a_00_3 = {53 75 62 20 44 6f 43 75 4d 45 4e 54 5f 4f 50 65 6e 28 29 3a 20 43 61 6c 6c } //00 00  Sub DoCuMENT_OPen(): Call
	condition:
		any of ($a_*)
 
}