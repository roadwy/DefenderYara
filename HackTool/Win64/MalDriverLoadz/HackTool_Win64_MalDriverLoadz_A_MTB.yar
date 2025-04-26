
rule HackTool_Win64_MalDriverLoadz_A_MTB{
	meta:
		description = "HackTool:Win64/MalDriverLoadz.A!MTB,SIGNATURE_TYPE_PEHSTR,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {f3 0f 7f 75 c7 66 44 89 75 b7 48 8b 55 0f 48 83 fa 07 76 41 48 8d 14 55 02 00 00 00 48 8b 4d f7 48 8b c1 48 81 fa 00 10 00 00 72 1c 48 83 c2 27 48 8b 49 f8 48 2b c1 } //1
		$a_01_1 = {5c 6b 64 6d 61 70 70 65 72 2d 6d 61 73 74 65 72 } //1 \kdmapper-master
		$a_01_2 = {5c 6e 61 6c 5c 73 72 63 5c 77 69 6e 6e 74 5f 77 64 6d 5c 64 72 69 76 65 72 } //1 \nal\src\winnt_wdm\driver
		$a_01_3 = {4e 74 4c 6f 61 64 44 72 69 76 65 72 } //1 NtLoadDriver
		$a_01_4 = {76 75 6c 6e 65 72 61 62 6c 65 20 64 72 69 76 65 72 } //1 vulnerable driver
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}