
rule Trojan_Win32_Vilsel_EN_MTB{
	meta:
		description = "Trojan:Win32/Vilsel.EN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {78 74 72 67 6b 68 70 76 74 66 6e 74 6e 72 78 76 6d 73 63 70 68 6b 67 } //1 xtrgkhpvtfntnrxvmscphkg
		$a_01_1 = {78 62 63 64 66 67 32 6c 6d 6e 70 72 73 74 76 } //1 xbcdfg2lmnprstv
		$a_01_2 = {67 65 74 68 6f 73 74 62 79 6e 61 6d 65 } //1 gethostbyname
		$a_01_3 = {61 72 74 75 70 49 6e 66 6f 30 53 79 52 65 6d 44 } //1 artupInfo0SyRemD
		$a_01_4 = {6f 6f 6c 68 65 6c 70 33 32 53 6e 61 70 73 68 6f 74 52 44 65 6c 65 } //1 oolhelp32SnapshotRDele
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}