
rule VirTool_Win32_VBInject_ADU{
	meta:
		description = "VirTool:Win32/VBInject.ADU,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {35 00 34 00 50 00 31 00 44 00 50 00 30 00 30 00 50 00 38 00 33 00 50 00 43 00 33 00 50 00 30 00 34 00 50 00 38 00 31 00 50 00 37 00 43 00 50 00 31 00 44 00 50 00 46 00 43 00 50 00 34 00 32 00 50 00 34 00 32 00 50 00 34 00 32 00 50 00 34 00 32 00 50 00 37 00 35 00 50 00 43 00 31 00 50 00 36 00 36 00 50 00 30 00 46 00 50 00 45 00 46 00 50 00 } //1 54P1DP00P83PC3P04P81P7CP1DPFCP42P42P42P42P75PC1P66P0FPEFP
		$a_03_1 = {3b fb 7f 57 68 ?? ?? ?? ?? 8b cf 8b 45 d4 2b 48 14 8b 40 0c ff 34 88 e8 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}