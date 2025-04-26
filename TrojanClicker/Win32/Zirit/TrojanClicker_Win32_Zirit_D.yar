
rule TrojanClicker_Win32_Zirit_D{
	meta:
		description = "TrojanClicker:Win32/Zirit.D,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 05 00 00 "
		
	strings :
		$a_01_0 = {43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e } //1 CurrentVersion\Run
		$a_01_1 = {66 69 72 73 74 63 6c 69 63 6b } //2 firstclick
		$a_01_2 = {6d 69 6e 63 6c 69 63 6b 74 69 6d 65 } //3 minclicktime
		$a_01_3 = {65 78 65 63 75 72 6c } //2 execurl
		$a_01_4 = {65 78 65 63 66 69 6c 65 } //2 execfile
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*2+(#a_01_2  & 1)*3+(#a_01_3  & 1)*2+(#a_01_4  & 1)*2) >=10
 
}