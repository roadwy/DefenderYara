
rule Trojan_Win32_Snakeklg_GB_MTB{
	meta:
		description = "Trojan:Win32/Snakeklg.GB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 04 00 00 "
		
	strings :
		$a_80_0 = {53 4e 41 4b 45 2d 4b 45 59 4c 4f 47 47 45 52 } //SNAKE-KEYLOGGER  10
		$a_80_1 = {53 2d 2d 2d 2d 2d 2d 2d 2d 4e 2d 2d 2d 2d 2d 2d 2d 2d 41 2d 2d 2d 2d 2d 2d 2d 2d 4b 2d 2d 2d 2d 2d 2d 2d 2d 45 } //S--------N--------A--------K--------E  1
		$a_02_2 = {4b 00 45 00 59 00 4c 00 4f 00 47 00 47 00 45 00 52 00 [0-1e] 53 00 [0-19] 4e 00 [0-19] 41 00 [0-19] 4b 00 [0-19] 45 00 } //1
		$a_02_3 = {4b 45 59 4c 4f 47 47 45 52 [0-1e] 53 [0-19] 4e [0-19] 41 [0-19] 4b [0-19] 45 } //1
	condition:
		((#a_80_0  & 1)*10+(#a_80_1  & 1)*1+(#a_02_2  & 1)*1+(#a_02_3  & 1)*1) >=11
 
}