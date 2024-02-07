
rule Backdoor_Win32_Farfli_BE{
	meta:
		description = "Backdoor:Win32/Farfli.BE,SIGNATURE_TYPE_PEHSTR_EXT,10 00 10 00 05 00 00 02 00 "
		
	strings :
		$a_01_0 = {4c 6f 61 64 5f 50 61 74 68 } //02 00  Load_Path
		$a_01_1 = {6e 65 74 73 76 63 73 } //03 00  netsvcs
		$a_01_2 = {53 59 53 54 45 4d 5c 43 75 72 72 65 6e 74 43 6f 6e 74 72 6f 6c 53 65 74 5c 53 65 72 76 69 63 65 73 5c 25 73 } //04 00  SYSTEM\CurrentControlSet\Services\%s
		$a_01_3 = {5c 65 73 65 6e 74 2e 64 6c 6c } //05 00  \esent.dll
		$a_01_4 = {25 73 5c 77 69 25 64 6e 64 2e 74 65 6d 70 } //00 00  %s\wi%dnd.temp
		$a_00_5 = {5d 04 00 00 4d 0b 03 } //80 5c 
	condition:
		any of ($a_*)
 
}