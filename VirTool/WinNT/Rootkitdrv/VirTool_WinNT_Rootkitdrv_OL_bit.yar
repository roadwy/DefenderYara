
rule VirTool_WinNT_Rootkitdrv_OL_bit{
	meta:
		description = "VirTool:WinNT/Rootkitdrv.OL!bit,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {62 6c 6f 67 2e 31 36 33 2e 63 6f 6d 2f 6d 6f 6c 6c 79 5f 79 61 64 61 67 72 6f 75 70 2f 70 72 6f 66 69 6c 65 } //1 blog.163.com/molly_yadagroup/profile
		$a_01_1 = {74 2e 71 71 2e 63 6f 6d 2f 63 68 75 61 6e 71 69 66 75 7a 68 75 32 30 31 38 } //1 t.qq.com/chuanqifuzhu2018
		$a_01_2 = {68 33 64 44 53 45 55 36 63 33 39 39 31 41 3d 3d } //1 h3dDSEU6c3991A==
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}