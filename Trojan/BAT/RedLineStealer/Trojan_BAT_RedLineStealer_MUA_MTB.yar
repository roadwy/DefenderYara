
rule Trojan_BAT_RedLineStealer_MUA_MTB{
	meta:
		description = "Trojan:BAT/RedLineStealer.MUA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {6f 70 65 6e 49 50 4c 6f 67 5f 52 65 67 69 64 } //1 openIPLog_Regid
		$a_01_1 = {64 65 63 72 79 70 74 } //1 decrypt
		$a_01_2 = {44 6f 77 6e 6c 6f 61 64 44 61 74 61 } //1 DownloadData
		$a_01_3 = {69 00 70 00 6c 00 6f 00 67 00 67 00 65 00 72 00 2e 00 6f 00 72 00 67 00 2f 00 31 00 71 00 70 00 74 00 66 00 37 00 } //1 iplogger.org/1qptf7
		$a_01_4 = {73 00 63 00 43 00 48 00 47 00 37 00 52 00 4c 00 77 00 71 00 43 00 72 00 46 00 4f 00 64 00 52 00 6d 00 64 00 } //1 scCHG7RLwqCrFOdRmd
		$a_01_5 = {7a 69 70 70 65 64 42 75 66 66 65 72 } //1 zippedBuffer
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}