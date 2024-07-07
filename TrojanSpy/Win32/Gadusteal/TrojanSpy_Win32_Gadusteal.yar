
rule TrojanSpy_Win32_Gadusteal{
	meta:
		description = "TrojanSpy:Win32/Gadusteal,SIGNATURE_TYPE_PEHSTR,07 00 07 00 07 00 00 "
		
	strings :
		$a_01_0 = {5c 44 61 6e 65 20 61 70 6c 69 6b 61 63 6a 69 5c 4e 6f 77 65 20 47 61 64 75 2d 47 61 64 75 5c } //1 \Dane aplikacji\Nowe Gadu-Gadu\
		$a_01_1 = {71 77 65 72 74 79 00 31 32 37 78 2e 79 6f 79 6f 2e 70 6c } //1
		$a_01_2 = {41 72 63 68 69 76 65 2e 64 62 } //1 Archive.db
		$a_01_3 = {50 72 6f 66 69 6c 65 2e 78 6d 6c } //1 Profile.xml
		$a_01_4 = {50 72 6f 66 69 6c 65 42 61 73 69 63 2e 78 6d 6c } //1 ProfileBasic.xml
		$a_01_5 = {43 6f 6e 74 61 63 74 4c 69 73 74 2e 78 6d 6c } //1 ContactList.xml
		$a_01_6 = {46 74 70 50 75 74 46 69 6c 65 41 } //1 FtpPutFileA
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=7
 
}