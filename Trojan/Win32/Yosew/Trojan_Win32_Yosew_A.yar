
rule Trojan_Win32_Yosew_A{
	meta:
		description = "Trojan:Win32/Yosew.A,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {2f 79 63 64 65 6c 2e 61 73 70 3f 61 63 74 69 6f 6e 3d 73 65 72 26 75 73 65 72 6e 61 6d 65 3d } //1 /ycdel.asp?action=ser&username=
		$a_01_1 = {2f 62 61 69 2f 71 71 7a 78 2e 74 78 74 3f 31 32 33 } //1 /bai/qqzx.txt?123
		$a_01_2 = {7a 68 65 6e 67 74 75 00 33 36 30 73 64 2e 65 78 65 00 00 00 67 67 73 61 66 65 2e 65 78 65 } //1
		$a_01_3 = {5c 78 73 65 6e 64 2e 74 6d 70 00 00 61 74 2b 00 5d 20 } //1
		$a_01_4 = {5c 73 79 73 74 65 6d 5c 6c 6f 63 6b 2e 64 61 74 } //1 \system\lock.dat
		$a_01_5 = {5c 59 53 57 4d 44 6c 6c } //1 \YSWMDll
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}