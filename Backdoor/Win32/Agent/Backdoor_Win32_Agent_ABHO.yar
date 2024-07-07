
rule Backdoor_Win32_Agent_ABHO{
	meta:
		description = "Backdoor:Win32/Agent.ABHO,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {6e 00 65 00 74 00 73 00 68 00 61 00 72 00 69 00 6e 00 67 00 73 00 69 00 74 00 65 00 2e 00 63 00 6f 00 6d 00 2f 00 67 00 65 00 74 00 74 00 61 00 73 00 6b 00 73 00 2e 00 70 00 68 00 70 00 } //1 netsharingsite.com/gettasks.php
		$a_01_1 = {74 00 68 00 65 00 6e 00 65 00 74 00 73 00 68 00 61 00 72 00 69 00 6e 00 67 00 2e 00 63 00 6f 00 6d 00 2f 00 67 00 65 00 74 00 74 00 61 00 73 00 6b 00 73 00 2e 00 70 00 68 00 70 00 } //1 thenetsharing.com/gettasks.php
		$a_01_2 = {62 61 63 6b 64 6f 6f 72 2d 76 34 2d 65 64 32 6b } //1 backdoor-v4-ed2k
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}