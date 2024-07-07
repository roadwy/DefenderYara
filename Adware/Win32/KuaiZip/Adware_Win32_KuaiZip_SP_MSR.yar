
rule Adware_Win32_KuaiZip_SP_MSR{
	meta:
		description = "Adware:Win32/KuaiZip.SP!MSR,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 05 00 00 "
		
	strings :
		$a_01_0 = {67 75 61 6e 77 61 6e 67 5f 30 30 31 } //1 guanwang_001
		$a_01_1 = {78 69 61 6f 79 75 2e 65 78 65 } //1 xiaoyu.exe
		$a_01_2 = {58 59 37 7a 44 61 74 61 2e 37 7a } //1 XY7zData.7z
		$a_01_3 = {53 00 45 00 4c 00 45 00 43 00 54 00 20 00 2a 00 20 00 46 00 52 00 4f 00 4d 00 20 00 57 00 69 00 6e 00 33 00 32 00 5f 00 42 00 49 00 4f 00 53 00 } //1 SELECT * FROM Win32_BIOS
		$a_01_4 = {78 00 69 00 61 00 6f 00 79 00 75 00 5f 00 49 00 6e 00 73 00 74 00 61 00 6c 00 6c 00 5f 00 46 00 65 00 6e 00 64 00 79 00 43 00 5f 00 } //1 xiaoyu_Install_FendyC_
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=4
 
}