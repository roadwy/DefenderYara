
rule Trojan_BAT_Downloader_BN_MTB{
	meta:
		description = "Trojan:BAT/Downloader.BN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 74 00 65 00 6d 00 70 00 75 00 72 00 69 00 2e 00 6f 00 72 00 67 00 2f 00 43 00 61 00 74 00 65 00 67 00 6f 00 72 00 79 00 73 00 74 00 6f 00 72 00 65 00 44 00 61 00 74 00 61 00 53 00 65 00 74 00 2e 00 78 00 73 00 64 00 } //01 00  http://tempuri.org/CategorystoreDataSet.xsd
		$a_01_1 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 74 00 65 00 6d 00 70 00 75 00 72 00 69 00 2e 00 6f 00 72 00 67 00 2f 00 44 00 61 00 73 00 68 00 42 00 6f 00 61 00 72 00 64 00 54 00 72 00 61 00 6e 00 73 00 61 00 63 00 74 00 69 00 6f 00 6e 00 44 00 61 00 74 00 61 00 53 00 65 00 74 00 2e 00 78 00 73 00 64 00 } //01 00  http://tempuri.org/DashBoardTransactionDataSet.xsd
		$a_01_2 = {43 3a 5c 55 73 65 72 73 5c 41 64 6d 69 6e 69 73 74 72 61 74 6f 72 5c 44 65 73 6b 74 6f 70 5c 45 61 73 79 53 74 6f 72 65 5c 6f 62 6a 5c 44 65 62 75 67 5c 46 61 6e 6b 6f 2e 70 64 62 } //01 00  C:\Users\Administrator\Desktop\EasyStore\obj\Debug\Fanko.pdb
		$a_01_3 = {44 65 62 75 67 67 61 62 6c 65 41 74 74 72 69 62 75 74 65 } //01 00  DebuggableAttribute
		$a_01_4 = {46 61 6e 6b 6f 2e 65 78 65 } //01 00  Fanko.exe
		$a_01_5 = {44 65 62 75 67 67 65 72 4e 6f 6e 55 73 65 72 43 6f 64 65 41 74 74 72 69 62 75 74 65 } //00 00  DebuggerNonUserCodeAttribute
	condition:
		any of ($a_*)
 
}