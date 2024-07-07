
rule Backdoor_Win32_Hupigon_FK{
	meta:
		description = "Backdoor:Win32/Hupigon.FK,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 05 00 00 "
		
	strings :
		$a_03_0 = {6e 6d 65 6e c7 45 90 01 01 74 53 75 62 90 00 } //2
		$a_03_1 = {8a 14 01 80 f2 62 88 10 40 ff 4d 90 01 01 75 f2 90 00 } //2
		$a_00_2 = {83 f8 7f 77 18 83 f8 14 72 13 } //2
		$a_00_3 = {5c 73 79 73 6c 6f 67 2e 64 61 74 } //1 \syslog.dat
		$a_00_4 = {5f 6b 61 73 70 65 72 73 6b 79 } //1 _kaspersky
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*2+(#a_00_2  & 1)*2+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=4
 
}