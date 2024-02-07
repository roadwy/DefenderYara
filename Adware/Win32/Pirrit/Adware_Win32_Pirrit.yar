
rule Adware_Win32_Pirrit{
	meta:
		description = "Adware:Win32/Pirrit,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {31 63 68 65 63 6b 41 6e 64 52 75 6e 50 69 72 72 69 74 28 29 } //01 00  1checkAndRunPirrit()
		$a_01_1 = {50 69 72 72 69 74 44 65 73 6b 74 6f 70 00 } //00 00  楐牲瑩敄歳潴p
	condition:
		any of ($a_*)
 
}
rule Adware_Win32_Pirrit_2{
	meta:
		description = "Adware:Win32/Pirrit,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {31 66 69 6e 69 73 68 65 64 44 6f 77 6e 6c 6f 61 64 49 6e 6a 65 63 74 69 6f 6e 43 6f 6e 74 65 6e 74 28 51 4e 65 74 77 6f 72 6b } //01 00  1finishedDownloadInjectionContent(QNetwork
		$a_01_1 = {76 61 72 20 70 72 74 4c 6f 61 64 65 72 } //01 00  var prtLoader
		$a_01_2 = {66 75 6e 63 74 69 6f 6e 20 70 72 74 49 6e 49 66 72 61 6d 65 } //00 00  function prtInIframe
	condition:
		any of ($a_*)
 
}
rule Adware_Win32_Pirrit_3{
	meta:
		description = "Adware:Win32/Pirrit,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {69 64 3d 22 70 69 72 72 69 74 5f 69 73 5f 73 65 72 76 69 63 65 } //01 00  id="pirrit_is_service
		$a_01_1 = {76 61 72 20 50 49 52 52 49 54 5f 49 53 5f 49 4e 53 54 41 4c 4c 45 44 } //01 00  var PIRRIT_IS_INSTALLED
		$a_01_2 = {76 61 72 20 50 49 52 52 49 54 5f 49 53 5f 53 45 52 56 49 43 45 } //01 00  var PIRRIT_IS_SERVICE
		$a_01_3 = {76 61 72 20 50 49 52 52 49 54 5f 45 58 54 49 44 } //01 00  var PIRRIT_EXTID
		$a_01_4 = {76 61 72 20 70 69 72 72 69 74 4c 6f 61 64 65 72 } //01 00  var pirritLoader
		$a_01_5 = {73 75 67 67 65 73 74 6f 72 2e 70 69 72 72 69 74 2e 63 6f 6d } //00 00  suggestor.pirrit.com
	condition:
		any of ($a_*)
 
}