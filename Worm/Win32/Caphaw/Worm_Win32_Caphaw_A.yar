
rule Worm_Win32_Caphaw_A{
	meta:
		description = "Worm:Win32/Caphaw.A,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 04 00 00 "
		
	strings :
		$a_01_0 = {2f 68 69 6a 61 63 6b 63 66 67 2f 70 6c 75 67 69 6e 73 2f 70 6c 75 67 69 6e } //2 /hijackcfg/plugins/plugin
		$a_01_1 = {66 6f 6c 64 65 72 73 3a 25 64 3b 3b 3b 73 70 72 65 61 64 3a 25 64 } //1 folders:%d;;;spread:%d
		$a_01_2 = {73 70 72 65 61 64 6d 75 74 65 78 } //2 spreadmutex
		$a_03_3 = {83 e8 02 74 2e 48 74 0c 48 75 90 01 01 c7 47 90 01 01 6e 65 74 00 eb 90 00 } //1
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*2+(#a_03_3  & 1)*1) >=6
 
}