
rule Trojan_Win32_SlowGambler_D_dha{
	meta:
		description = "Trojan:Win32/SlowGambler.D!dha,SIGNATURE_TYPE_CMDHSTR_EXT,1e 00 1e 00 03 00 00 "
		
	strings :
		$a_01_0 = {73 00 63 00 68 00 74 00 61 00 73 00 6b 00 73 00 2e 00 65 00 78 00 65 00 } //10 schtasks.exe
		$a_01_1 = {2f 00 63 00 72 00 65 00 61 00 74 00 65 00 20 00 2f 00 74 00 6e 00 20 00 41 00 6e 00 69 00 6d 00 61 00 6c 00 53 00 6f 00 66 00 74 00 55 00 70 00 64 00 61 00 74 00 65 00 5c 00 41 00 6e 00 69 00 6d 00 61 00 6c 00 53 00 6f 00 66 00 74 00 55 00 70 00 64 00 61 00 74 00 65 00 72 00 20 00 2f 00 74 00 72 00 } //10 /create /tn AnimalSoftUpdate\AnimalSoftUpdater /tr
		$a_01_2 = {2f 00 73 00 63 00 20 00 6f 00 6e 00 63 00 65 00 20 00 2f 00 73 00 74 00 } //10 /sc once /st
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10+(#a_01_2  & 1)*10) >=30
 
}