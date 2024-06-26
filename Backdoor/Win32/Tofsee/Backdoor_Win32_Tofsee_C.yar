
rule Backdoor_Win32_Tofsee_C{
	meta:
		description = "Backdoor:Win32/Tofsee.C,SIGNATURE_TYPE_PEHSTR,0f 00 0f 00 0b 00 00 01 00 "
		
	strings :
		$a_01_0 = {50 6c 75 67 69 6e 20 72 65 73 74 61 72 74 65 64 } //01 00  Plugin restarted
		$a_01_1 = {6c 6f 63 61 6c 63 66 67 } //01 00  localcfg
		$a_01_2 = {55 53 42 20 65 72 72 73 } //01 00  USB errs
		$a_01_3 = {55 53 42 20 73 63 63 73 } //01 00  USB sccs
		$a_01_4 = {55 53 42 20 64 72 76 73 } //01 00  USB drvs
		$a_01_5 = {75 73 62 3a 20 64 6f 6e 65 } //01 00  usb: done
		$a_01_6 = {5b 61 75 74 6f 72 75 6e 5d } //01 00  [autorun]
		$a_01_7 = {73 68 65 6c 6c 65 78 65 63 75 74 65 3d } //01 00  shellexecute=
		$a_01_8 = {52 45 43 59 43 4c 45 52 } //01 00  RECYCLER
		$a_01_9 = {75 73 62 3a 20 44 72 69 76 65 20 27 25 73 27 20 66 6f 75 6e 64 } //01 00  usb: Drive '%s' found
		$a_01_10 = {61 75 74 6f 72 75 6e 2e 69 6e 66 } //00 00  autorun.inf
		$a_01_11 = {00 87 10 00 00 5c b6 bf d8 93 4a } //db 53 
	condition:
		any of ($a_*)
 
}