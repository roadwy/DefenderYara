
rule TrojanProxy_Win32_Delf_AN{
	meta:
		description = "TrojanProxy:Win32/Delf.AN,SIGNATURE_TYPE_PEHSTR_EXT,08 00 07 00 0a 00 00 "
		
	strings :
		$a_00_0 = {6d 61 69 6c 20 65 78 63 68 61 6e 67 65 72 20 3d 20 } //1 mail exchanger = 
		$a_00_1 = {44 6e 73 52 65 63 6f 72 64 4c 69 73 74 46 72 65 65 } //1 DnsRecordListFree
		$a_00_2 = {49 6e 74 65 72 6e 65 74 43 72 61 63 6b 55 72 6c 41 } //1 InternetCrackUrlA
		$a_00_3 = {6e 73 6c 6f 6f 6b 75 70 20 3c } //1 nslookup <
		$a_00_4 = {70 6e 67 2f 70 6e 67 2e 65 78 65 } //1 png/png.exe
		$a_00_5 = {6a 70 67 2f 6a 70 67 2e 65 78 65 } //1 jpg/jpg.exe
		$a_00_6 = {63 68 67 69 66 2e 65 78 65 } //1 chgif.exe
		$a_00_7 = {2f 63 67 69 2d 73 63 72 69 70 74 2f 72 65 70 65 61 74 65 72 6d 33 2e 66 63 67 69 3f 76 35 } //1 /cgi-script/repeaterm3.fcgi?v5
		$a_01_8 = {4d 6f 7a 69 6c 6c 61 2f 35 2e 30 20 28 57 69 6e 64 6f 77 73 3b 20 55 3b 20 57 69 6e 64 6f 77 73 20 4e 54 20 35 2e 31 3b 20 72 75 2d 52 55 3b 20 72 76 3a } //1 Mozilla/5.0 (Windows; U; Windows NT 5.1; ru-RU; rv:
		$a_01_9 = {53 65 72 76 69 63 65 50 61 63 6b 46 69 6c 65 73 } //1 ServicePackFiles
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1+(#a_00_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1) >=7
 
}