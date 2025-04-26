
rule Worm_Win32_SillyShareCopy_AL{
	meta:
		description = "Worm:Win32/SillyShareCopy.AL,SIGNATURE_TYPE_PEHSTR,06 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {46 00 3a 00 5c 00 53 00 79 00 73 00 5c 00 77 00 6a 00 72 00 5c 00 56 00 42 00 5c 00 } //2 F:\Sys\wjr\VB\
		$a_01_1 = {5b 00 49 00 6e 00 74 00 65 00 72 00 6e 00 65 00 74 00 53 00 68 00 6f 00 72 00 74 00 63 00 75 00 74 00 5d 00 } //1 [InternetShortcut]
		$a_01_2 = {50 00 50 00 53 00 20 00 41 00 63 00 63 00 65 00 6c 00 65 00 72 00 61 00 74 00 6f 00 72 00 } //2 PPS Accelerator
		$a_01_3 = {53 00 68 00 6f 00 77 00 53 00 75 00 70 00 65 00 72 00 48 00 69 00 64 00 64 00 65 00 6e 00 } //1 ShowSuperHidden
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*2+(#a_01_3  & 1)*1) >=4
 
}