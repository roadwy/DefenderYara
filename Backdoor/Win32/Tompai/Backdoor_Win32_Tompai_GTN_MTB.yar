
rule Backdoor_Win32_Tompai_GTN_MTB{
	meta:
		description = "Backdoor:Win32/Tompai.GTN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_80_0 = {4b 4c 70 72 6f 6a 4d 61 69 6e 2e 65 78 65 } //KLprojMain.exe  1
		$a_01_1 = {61 64 6a 5f 66 70 74 61 6e } //1 adj_fptan
		$a_01_2 = {45 56 45 4e 54 5f 53 49 4e 4b 5f 2a } //1 EVENT_SINK_*
		$a_01_3 = {44 6c 6c 46 51 41 6d 6b 70 } //1 DllFQAmkp
		$a_01_4 = {58 6c 4f 47 74 47 55 } //1 XlOGtGU
	condition:
		((#a_80_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}