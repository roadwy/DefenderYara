
rule Backdoor_Win32_Hupigon_RA{
	meta:
		description = "Backdoor:Win32/Hupigon.RA,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 09 00 00 "
		
	strings :
		$a_00_0 = {55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 41 } //1 URLDownloadToFileA
		$a_00_1 = {4f 70 65 6e 53 43 4d 61 6e 61 67 65 72 41 } //1 OpenSCManagerA
		$a_01_2 = {46 69 6e 61 6c 46 61 6e 74 61 73 79 } //1 FinalFantasy
		$a_01_3 = {44 65 6c 65 74 65 6d 65 2e 62 61 74 00 00 00 00 ff ff ff ff 07 00 00 00 3a 52 65 70 65 61 74 00 ff ff ff ff 05 00 00 00 64 65 6c 20 } //1
		$a_00_4 = {4d 61 69 6e 53 65 72 76 65 72 } //1 MainServer
		$a_00_5 = {53 59 53 54 45 4d 5c 43 75 72 72 65 6e 74 43 6f 6e 74 72 6f 6c 53 65 74 5c 53 65 72 76 69 63 65 73 5c } //1 SYSTEM\CurrentControlSet\Services\
		$a_00_6 = {53 4f 46 54 57 41 52 45 5c 42 6f 72 6c 61 6e 64 5c 44 65 6c 70 68 69 5c 52 54 4c } //1 SOFTWARE\Borland\Delphi\RTL
		$a_01_7 = {46 46 53 65 72 76 65 72 2e 65 78 65 } //1 FFServer.exe
		$a_01_8 = {23 57 69 6e 64 6f 77 73 4d 61 6e 61 67 65 6d 65 6e 74 43 68 65 63 6b 52 61 64 69 6f 42 6f 78 43 6c 69 63 6b 2a } //1 #WindowsManagementCheckRadioBoxClick*
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1) >=7
 
}