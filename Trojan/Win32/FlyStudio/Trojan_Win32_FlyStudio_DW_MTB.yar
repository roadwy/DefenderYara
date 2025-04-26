
rule Trojan_Win32_FlyStudio_DW_MTB{
	meta:
		description = "Trojan:Win32/FlyStudio.DW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {74 2e 71 71 2e 63 6f 6d 2f 6d 69 6d 61 68 65 6e 6a 69 61 6e 64 61 6e } //1 t.qq.com/mimahenjiandan
		$a_01_1 = {72 3d 31 33 32 36 30 32 35 37 36 31 34 35 33 } //1 r=1326025761453
		$a_01_2 = {6d 2e 71 7a 6f 6e 65 2e 71 71 2e 63 6f 6d 2f 63 67 69 2d 62 69 6e 2f 6e 65 77 2f 6d 73 67 62 5f 61 64 64 61 6e 73 77 65 72 2e 63 67 69 } //1 m.qzone.qq.com/cgi-bin/new/msgb_addanswer.cgi
		$a_01_3 = {75 73 65 72 2e 71 7a 6f 6e 65 2e 71 71 2e 63 6f 6d 2f 38 32 37 38 32 32 32 38 35 } //1 user.qzone.qq.com/827822285
		$a_01_4 = {63 63 62 66 64 36 38 62 35 66 63 65 62 36 32 37 30 37 61 39 65 34 63 65 38 37 62 38 63 38 31 33 } //1 ccbfd68b5fceb62707a9e4ce87b8c813
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}