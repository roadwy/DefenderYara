
rule Trojan_Win32_Fakovid_PA_MSR{
	meta:
		description = "Trojan:Win32/Fakovid.PA!MSR,SIGNATURE_TYPE_PEHSTR,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {63 6f 76 69 64 2d 31 39 20 69 6e 66 6f 72 6d 65 72 2e 70 64 62 } //1 covid-19 informer.pdb
		$a_01_1 = {63 6f 76 69 64 2d 31 39 20 69 6e 66 6f 72 6d 65 72 2e 65 78 65 } //1 covid-19 informer.exe
		$a_01_2 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 74 00 69 00 6e 00 79 00 2e 00 63 00 63 00 2f 00 } //1 http://tiny.cc/
		$a_01_3 = {43 00 3a 00 5c 00 5c 00 48 00 69 00 64 00 64 00 65 00 6e 00 46 00 6f 00 6c 00 64 00 65 00 72 00 5c 00 5c 00 } //1 C:\\HiddenFolder\\
		$a_01_4 = {73 00 65 00 74 00 75 00 70 00 } //1 setup
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}