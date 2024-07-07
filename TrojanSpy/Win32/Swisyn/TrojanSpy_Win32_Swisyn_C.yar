
rule TrojanSpy_Win32_Swisyn_C{
	meta:
		description = "TrojanSpy:Win32/Swisyn.C,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {5c 00 50 00 75 00 73 00 6d 00 69 00 6e 00 74 00 5c 00 73 00 76 00 63 00 68 00 6f 00 73 00 74 00 2e 00 65 00 78 00 65 00 } //1 \Pusmint\svchost.exe
		$a_01_1 = {68 00 6f 00 6f 00 6b 00 6d 00 69 00 62 00 61 00 6f 00 2e 00 61 00 73 00 70 00 3f 00 6d 00 73 00 67 00 3d 00 } //1 hookmibao.asp?msg=
		$a_01_2 = {5c 00 50 00 75 00 73 00 6d 00 69 00 6e 00 74 00 5c 00 6a 00 69 00 65 00 74 00 75 00 2e 00 6a 00 70 00 67 00 } //1 \Pusmint\jietu.jpg
		$a_01_3 = {4c 00 61 00 73 00 74 00 51 00 51 00 55 00 69 00 6e 00 } //1 LastQQUin
		$a_01_4 = {64 00 6e 00 66 00 2e 00 65 00 78 00 65 00 } //1 dnf.exe
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}