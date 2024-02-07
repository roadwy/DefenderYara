
rule Trojan_O97M_TrojanDownloader_RDB_MTB{
	meta:
		description = "Trojan:O97M/TrojanDownloader.RDB!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 03 00 00 02 00 "
		
	strings :
		$a_01_0 = {4d 77 41 75 41 44 59 41 4f 41 41 75 41 44 55 41 4e 67 41 75 41 44 49 41 4d 77 41 79 41 43 49 41 4c 41 41 78 41 44 49 41 4e 41 41 30 41 44 45 41 4b 51 } //02 00  MwAuADYAOAAuADUANgAuADIAMwAyACIALAAxADIANAA0ADEAKQ
		$a_01_1 = {70 6f 77 65 72 73 68 65 6c 6c 20 2d 65 } //02 00  powershell -e
		$a_01_2 = {43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 57 73 63 72 69 70 74 2e 73 68 65 6c 6c 22 29 2e 52 75 6e } //00 00  CreateObject("Wscript.shell").Run
	condition:
		any of ($a_*)
 
}