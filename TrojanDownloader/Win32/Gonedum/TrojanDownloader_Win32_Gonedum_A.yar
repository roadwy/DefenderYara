
rule TrojanDownloader_Win32_Gonedum_A{
	meta:
		description = "TrojanDownloader:Win32/Gonedum.A,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {42 44 39 36 43 35 35 36 2d 36 35 41 33 2d 31 31 44 30 2d 39 38 33 41 2d 30 30 43 30 34 46 43 32 39 45 33 36 } //1 BD96C556-65A3-11D0-983A-00C04FC29E36
		$a_01_1 = {73 65 74 20 74 6d 70 20 3d 20 46 2e 42 75 69 6c 64 70 61 74 68 28 74 6d 70 2c 66 6e 61 6d 65 31 29 } //1 set tmp = F.Buildpath(tmp,fname1)
		$a_01_2 = {53 2e 73 61 76 65 74 6f 66 69 6c 65 20 66 6e 61 6d 65 31 2c 32 } //1 S.savetofile fname1,2
		$a_01_3 = {51 2e 53 68 65 6c 6c 65 78 65 63 75 74 65 20 66 6e 61 6d 65 31 2c 22 22 2c 22 22 2c 22 6f 70 65 6e 22 2c 30 } //1 Q.Shellexecute fname1,"","","open",0
		$a_01_4 = {66 6e 61 6d 65 31 3d 22 67 30 31 64 2e 63 6f 6d } //1 fname1="g01d.com
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}