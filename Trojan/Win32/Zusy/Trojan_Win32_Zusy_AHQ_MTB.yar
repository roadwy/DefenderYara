
rule Trojan_Win32_Zusy_AHQ_MTB{
	meta:
		description = "Trojan:Win32/Zusy.AHQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,ffffff96 00 ffffff96 00 05 00 00 "
		
	strings :
		$a_81_0 = {25 77 73 5c 6b 65 79 6c 6f 67 61 6c 6c 2e 74 78 74 } //10 %ws\keylogall.txt
		$a_81_1 = {70 69 70 65 5c 73 73 73 74 65 61 6c 65 72 } //20 pipe\ssstealer
		$a_81_2 = {2f 66 69 6c 65 6e 61 6d 65 62 79 70 61 73 73 } //30 /filenamebypass
		$a_81_3 = {2f 62 72 6f 77 73 65 72 73 68 65 6c 6c } //40 /browsershell
		$a_81_4 = {2f 75 64 75 6e 77 61 6c 6c 65 74 } //50 /udunwallet
	condition:
		((#a_81_0  & 1)*10+(#a_81_1  & 1)*20+(#a_81_2  & 1)*30+(#a_81_3  & 1)*40+(#a_81_4  & 1)*50) >=150
 
}