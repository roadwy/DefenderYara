
rule Backdoor_Win32_Androm_BG_MTB{
	meta:
		description = "Backdoor:Win32/Androm.BG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_03_0 = {8b ff 8b 0d [0-04] 8a 94 31 [0-04] a1 [0-04] 88 14 30 81 3d [0-04] ab 05 00 00 75 } //2
		$a_03_1 = {3d cb d9 0b 00 75 06 81 c1 [0-04] 40 3d 3d a6 15 00 7c } //1
		$a_01_2 = {81 fe 2b ac 01 00 7e 08 81 fb e1 be f5 00 75 09 46 81 fe b6 2d bc 1e 7c } //1
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1) >=4
 
}