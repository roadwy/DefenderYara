
rule Backdoor_Win32_Prorat_BY{
	meta:
		description = "Backdoor:Win32/Prorat.BY,SIGNATURE_TYPE_PEHSTR,05 00 04 00 05 00 00 "
		
	strings :
		$a_01_0 = {70 63 2d 72 61 74 2e 63 6f 6d } //1 pc-rat.com
		$a_01_1 = {4b 61 73 70 65 72 73 6b 79 3a 61 76 70 2e 65 78 65 2f 4b 41 56 53 76 63 55 49 2e 65 78 65 } //1 Kaspersky:avp.exe/KAVSvcUI.exe
		$a_01_2 = {53 79 6d 61 6e 74 65 63 20 4e 6f 72 74 6f 6e 3a 63 63 61 70 70 2e 65 78 65 2f 63 63 65 76 74 6d 67 72 2e 65 78 65 } //1 Symantec Norton:ccapp.exe/ccevtmgr.exe
		$a_01_3 = {45 53 45 54 20 4e 4f 44 33 32 3a 65 67 75 69 2e 65 78 65 2f 65 6b 72 6e 2e 65 78 65 } //1 ESET NOD32:egui.exe/ekrn.exe
		$a_01_4 = {40 6d 65 6d 62 65 72 73 2e 33 33 32 32 2e 6f 72 67 2f 64 79 6e 64 6e 73 2f 75 70 64 61 74 65 3f 73 79 73 74 65 6d 3d 64 79 6e 64 6e 73 26 68 6f 73 74 6e 61 6d 65 3d } //1 @members.3322.org/dyndns/update?system=dyndns&hostname=
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=4
 
}