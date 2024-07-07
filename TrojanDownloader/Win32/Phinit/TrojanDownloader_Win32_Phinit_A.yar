
rule TrojanDownloader_Win32_Phinit_A{
	meta:
		description = "TrojanDownloader:Win32/Phinit.A,SIGNATURE_TYPE_PEHSTR_EXT,30 01 30 01 07 00 00 "
		
	strings :
		$a_02_0 = {25 73 5c 25 73 2e 69 6e 69 90 02 04 25 73 90 00 } //100
		$a_00_1 = {44 6c 6c 43 61 6e 55 6e 6c 6f 61 64 4e 6f 77 } //100 DllCanUnloadNow
		$a_00_2 = {25 59 2d 25 6d 2d 25 64 } //100 %Y-%m-%d
		$a_00_3 = {68 74 74 70 3a 2f 2f 25 73 2f 75 70 2f 75 70 64 61 74 65 2e 68 74 6d } //3 http://%s/up/update.htm
		$a_00_4 = {68 74 74 70 3a 2f 2f 25 73 2f 70 61 67 65 2f 61 70 2e 61 73 70 } //3 http://%s/page/ap.asp
		$a_00_5 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 45 78 70 6c 6f 72 65 72 5c 53 68 65 6c 6c 20 46 6f 6c 64 65 72 73 } //1 Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders
		$a_00_6 = {53 59 53 54 45 4d 5c 43 75 72 72 65 6e 74 43 6f 6e 74 72 6f 6c 53 65 74 5c 53 65 72 76 69 63 65 73 5c 45 76 65 6e 74 6c 6f 67 } //1 SYSTEM\CurrentControlSet\Services\Eventlog
	condition:
		((#a_02_0  & 1)*100+(#a_00_1  & 1)*100+(#a_00_2  & 1)*100+(#a_00_3  & 1)*3+(#a_00_4  & 1)*3+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1) >=304
 
}