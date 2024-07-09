
rule PWS_Win32_Delf_EM{
	meta:
		description = "PWS:Win32/Delf.EM,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 0b 00 00 "
		
	strings :
		$a_02_0 = {8b 45 fc 83 78 ?? 00 74 ?? 8b 45 fc 83 78 ?? 00 74 } //2
		$a_00_1 = {6d 61 6c 77 61 72 65 } //2 malware
		$a_00_2 = {53 65 6c 66 44 65 6c 2e 62 61 74 } //2 SelfDel.bat
		$a_00_3 = {70 72 65 6c 6c 65 72 73 74 61 79 2e 63 6f 2e 7a 61 } //2 prellerstay.co.za
		$a_00_4 = {77 63 78 5f 66 74 70 2e 69 6e 69 } //1 wcx_ftp.ini
		$a_00_5 = {48 69 73 74 6f 72 79 2e 64 61 74 } //1 History.dat
		$a_00_6 = {73 69 74 65 6d 61 6e 61 67 65 72 2e 78 6d 6c } //1 sitemanager.xml
		$a_00_7 = {53 65 72 76 65 72 2e 50 61 73 73 } //1 Server.Pass
		$a_00_8 = {61 64 64 72 62 6b 2e 64 61 74 } //1 addrbk.dat
		$a_00_9 = {73 69 67 6e 6f 6e 73 2e 74 78 74 } //1 signons.txt
		$a_00_10 = {66 74 70 6c 69 73 74 2e 74 78 74 } //1 ftplist.txt
	condition:
		((#a_02_0  & 1)*2+(#a_00_1  & 1)*2+(#a_00_2  & 1)*2+(#a_00_3  & 1)*2+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1+(#a_00_7  & 1)*1+(#a_00_8  & 1)*1+(#a_00_9  & 1)*1+(#a_00_10  & 1)*1) >=10
 
}