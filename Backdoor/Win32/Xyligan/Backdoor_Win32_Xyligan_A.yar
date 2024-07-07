
rule Backdoor_Win32_Xyligan_A{
	meta:
		description = "Backdoor:Win32/Xyligan.A,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_03_0 = {80 33 25 43 90 90 81 fb 90 09 08 00 72 f2 90 90 bb 00 10 40 00 90 00 } //1
		$a_01_1 = {7e 1b 8a 84 0c 0c 01 00 00 04 14 88 84 0c 0c 02 00 00 34 06 88 44 0c 0c 41 3b ca 7c e5 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=1
 
}