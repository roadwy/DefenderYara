
rule Trojan_Win32_DelfInject_MK_MTB{
	meta:
		description = "Trojan:Win32/DelfInject.MK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,3c 00 3c 00 05 00 00 "
		
	strings :
		$a_01_0 = {75 5f 53 63 72 65 65 6e 53 70 79 } //15 u_ScreenSpy
		$a_01_1 = {75 5f 56 69 64 65 6f 53 70 79 } //15 u_VideoSpy
		$a_01_2 = {76 75 5f 4d 65 6d 52 75 6e 45 78 65 } //15 vu_MemRunExe
		$a_01_3 = {6e 75 5f 46 75 6e 50 72 6f 63 } //10 nu_FunProc
		$a_01_4 = {75 5f 52 65 61 64 43 4d 44 } //5 u_ReadCMD
	condition:
		((#a_01_0  & 1)*15+(#a_01_1  & 1)*15+(#a_01_2  & 1)*15+(#a_01_3  & 1)*10+(#a_01_4  & 1)*5) >=60
 
}