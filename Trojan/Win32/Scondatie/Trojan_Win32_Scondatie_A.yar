
rule Trojan_Win32_Scondatie_A{
	meta:
		description = "Trojan:Win32/Scondatie.A,SIGNATURE_TYPE_PEHSTR_EXT,6f 00 6f 00 06 00 00 "
		
	strings :
		$a_01_0 = {44 4d 54 4f 4f 4c } //100 DMTOOL
		$a_01_1 = {46 69 6c 65 73 5c 61 5c 73 79 6e 65 63 2e 74 78 74 } //10 Files\a\synec.txt
		$a_01_2 = {4d 65 65 74 69 6e 67 73 5c 61 5c 73 79 6e 65 63 2e 65 78 65 } //10 Meetings\a\synec.exe
		$a_03_3 = {78 69 61 6e 67 78 69 2e 90 11 03 00 00 } //1
		$a_01_4 = {6a 70 67 74 75 2e 64 61 74 } //1 jpgtu.dat
		$a_01_5 = {68 61 6f 74 75 2e 64 61 74 } //1 haotu.dat
	condition:
		((#a_01_0  & 1)*100+(#a_01_1  & 1)*10+(#a_01_2  & 1)*10+(#a_03_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=111
 
}