
rule Backdoor_Win32_Tofsee_C{
	meta:
		description = "Backdoor:Win32/Tofsee.C,SIGNATURE_TYPE_PEHSTR,0f 00 0f 00 0b 00 00 "
		
	strings :
		$a_01_0 = {50 6c 75 67 69 6e 20 72 65 73 74 61 72 74 65 64 } //1 Plugin restarted
		$a_01_1 = {6c 6f 63 61 6c 63 66 67 } //1 localcfg
		$a_01_2 = {55 53 42 20 65 72 72 73 } //1 USB errs
		$a_01_3 = {55 53 42 20 73 63 63 73 } //1 USB sccs
		$a_01_4 = {55 53 42 20 64 72 76 73 } //1 USB drvs
		$a_01_5 = {75 73 62 3a 20 64 6f 6e 65 } //1 usb: done
		$a_01_6 = {5b 61 75 74 6f 72 75 6e 5d } //1 [autorun]
		$a_01_7 = {73 68 65 6c 6c 65 78 65 63 75 74 65 3d } //1 shellexecute=
		$a_01_8 = {52 45 43 59 43 4c 45 52 } //1 RECYCLER
		$a_01_9 = {75 73 62 3a 20 44 72 69 76 65 20 27 25 73 27 20 66 6f 75 6e 64 } //1 usb: Drive '%s' found
		$a_01_10 = {61 75 74 6f 72 75 6e 2e 69 6e 66 } //1 autorun.inf
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1) >=15
 
}