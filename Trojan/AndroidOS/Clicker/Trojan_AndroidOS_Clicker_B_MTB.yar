
rule Trojan_AndroidOS_Clicker_B_MTB{
	meta:
		description = "Trojan:AndroidOS/Clicker.B!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 05 00 00 "
		
	strings :
		$a_00_0 = {4c 63 6f 6d 2f 69 61 70 70 2f 61 70 70 2f 6c 6f 67 6f 41 63 74 69 76 69 74 79 } //2 Lcom/iapp/app/logoActivity
		$a_00_1 = {79 75 76 30 2e 78 6d 6c } //1 yuv0.xml
		$a_00_2 = {2f 69 41 70 70 2f 44 6f 77 6e 6c 6f 61 64 46 69 6c 65 44 69 72 2f 54 65 6d 70 44 65 66 61 75 6c 74 44 6f 77 6e 46 69 6c 65 } //1 /iApp/DownloadFileDir/TempDefaultDownFile
		$a_00_3 = {63 6c 69 63 6b 69 } //1 clicki
		$a_00_4 = {74 6f 75 63 68 6d 6f 6e 69 74 6f 72 } //1 touchmonitor
	condition:
		((#a_00_0  & 1)*2+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=6
 
}