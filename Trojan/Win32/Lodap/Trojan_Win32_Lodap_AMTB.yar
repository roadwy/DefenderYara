
rule Trojan_Win32_Lodap_AMTB{
	meta:
		description = "Trojan:Win32/Lodap!AMTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 09 00 00 "
		
	strings :
		$a_80_0 = {71 63 72 6a 7a 73 68 40 67 } //qcrjzsh@g  2
		$a_80_1 = {69 5c 56 42 36 2e 4f 4c 42 56 } //i\VB6.OLBV  2
		$a_80_2 = {45 56 45 4e 54 5f 53 49 4e 4b 5f 41 64 64 52 65 66 44 } //EVENT_SINK_AddRefD  2
		$a_80_3 = {76 62 36 63 68 73 2e 64 6c 6c 2e } //vb6chs.dll.  2
		$a_80_4 = {50 5f 70 2f 6b 6e 65 6c 45 78 69 } //P_p/knelExi  2
		$a_80_5 = {61 77 61 72 64 2e 65 78 65 } //award.exe  2
		$a_80_6 = {55 6e 69 6e 73 74 2e 65 78 65 } //Uninst.exe  -100
		$a_80_7 = {55 6e 69 6e 73 74 61 6c 6c 65 72 2e 65 78 65 } //Uninstaller.exe  -100
		$a_80_8 = {55 6e 69 6e 73 74 61 6c 2e 65 78 65 } //Uninstal.exe  -100
	condition:
		((#a_80_0  & 1)*2+(#a_80_1  & 1)*2+(#a_80_2  & 1)*2+(#a_80_3  & 1)*2+(#a_80_4  & 1)*2+(#a_80_5  & 1)*2+(#a_80_6  & 1)*-100+(#a_80_7  & 1)*-100+(#a_80_8  & 1)*-100) >=12
 
}