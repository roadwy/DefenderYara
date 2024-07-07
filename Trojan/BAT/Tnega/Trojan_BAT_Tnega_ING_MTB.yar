
rule Trojan_BAT_Tnega_ING_MTB{
	meta:
		description = "Trojan:BAT/Tnega.ING!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 39 00 31 00 2e 00 32 00 34 00 31 00 2e 00 31 00 39 00 2e 00 35 00 32 00 } //1 http://91.241.19.52
		$a_01_1 = {52 00 75 00 6e 00 74 00 69 00 6d 00 65 00 62 00 72 00 6f 00 6b 00 65 00 72 00 2e 00 65 00 78 00 65 00 } //1 Runtimebroker.exe
		$a_81_2 = {52 61 77 5a 69 70 41 6e 64 41 65 73 } //1 RawZipAndAes
		$a_81_3 = {44 6f 77 6e 6c 6f 61 64 44 61 74 61 } //1 DownloadData
		$a_81_4 = {50 72 6f 63 65 73 73 53 74 61 72 74 49 6e 66 6f } //1 ProcessStartInfo
		$a_81_5 = {67 65 74 5f 53 74 61 72 74 75 70 50 61 74 68 } //1 get_StartupPath
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1) >=6
 
}