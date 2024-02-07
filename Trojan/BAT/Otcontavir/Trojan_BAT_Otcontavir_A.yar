
rule Trojan_BAT_Otcontavir_A{
	meta:
		description = "Trojan:BAT/Otcontavir.A,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 08 00 00 04 00 "
		
	strings :
		$a_03_0 = {3a 00 2f 00 2f 00 6c 00 61 00 6c 00 61 00 78 00 2e 00 63 00 61 00 74 00 2f 00 90 02 10 2f 00 75 00 70 00 2e 00 70 00 68 00 70 00 90 00 } //02 00 
		$a_01_1 = {4f 75 74 6c 6f 6f 6b 43 6f 6e 74 61 63 74 73 56 69 65 77 65 72 } //01 00  OutlookContactsViewer
		$a_01_2 = {55 70 6c 6f 61 64 45 6d 61 69 6c 4c 69 73 74 } //01 00  UploadEmailList
		$a_01_3 = {52 65 64 65 6d 70 74 69 6f 6e 4c 6f 61 64 65 72 } //01 00  RedemptionLoader
		$a_01_4 = {50 72 6f 63 65 73 45 6d 61 69 6c 42 6f 64 79 } //01 00  ProcesEmailBody
		$a_01_5 = {47 65 74 4d 61 69 6c 46 72 6f 6d 41 6c 6c 41 63 63 6f 75 6e 74 } //01 00  GetMailFromAllAccount
		$a_01_6 = {47 65 74 4d 61 69 6c 73 46 72 6f 6d 48 65 61 64 65 72 73 } //01 00  GetMailsFromHeaders
		$a_01_7 = {3d 00 3d 00 3d 00 3d 00 3d 00 53 00 54 00 41 00 52 00 54 00 2d 00 4c 00 49 00 53 00 54 00 2d 00 46 00 52 00 4f 00 4d 00 2d 00 43 00 4f 00 4e 00 54 00 41 00 43 00 54 00 53 00 3d 00 3d 00 3d 00 3d 00 3d 00 } //00 00  =====START-LIST-FROM-CONTACTS=====
	condition:
		any of ($a_*)
 
}