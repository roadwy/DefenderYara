
rule Trojan_Win32_TaskSchedulerQakBot_B{
	meta:
		description = "Trojan:Win32/TaskSchedulerQakBot.B,SIGNATURE_TYPE_CMDHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_00_0 = {73 00 63 00 68 00 74 00 61 00 73 00 6b 00 73 00 2e 00 65 00 78 00 65 00 } //1 schtasks.exe
		$a_00_1 = {2f 00 63 00 72 00 65 00 61 00 74 00 65 00 } //1 /create
		$a_00_2 = {6e 00 74 00 20 00 61 00 75 00 74 00 68 00 6f 00 72 00 69 00 74 00 79 00 5c 00 73 00 79 00 73 00 74 00 65 00 6d 00 } //1 nt authority\system
		$a_00_3 = {2f 00 74 00 6e 00 } //1 /tn
		$a_00_4 = {2f 00 74 00 72 00 } //1 /tr
		$a_00_5 = {2f 00 73 00 63 00 20 00 6f 00 6e 00 63 00 65 00 } //1 /sc once
		$a_00_6 = {2f 00 65 00 74 00 } //1 /et
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1) >=7
 
}