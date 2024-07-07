
rule PWS_Win32_Dyzap_R{
	meta:
		description = "PWS:Win32/Dyzap.R,SIGNATURE_TYPE_PEHSTR,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {5a 77 72 75 65 75 65 72 70 63 54 68 72 65 61 64 } //1 ZwrueuerpcThread
		$a_01_1 = {2d 00 5a 00 77 00 51 00 75 00 65 00 75 00 65 00 41 00 70 00 63 00 54 00 68 00 72 00 65 00 61 00 64 00 3a 00 } //1 -ZwQueueApcThread:
		$a_01_2 = {67 00 6f 00 6f 00 67 00 6c 00 65 00 75 00 70 00 64 00 61 00 74 00 65 00 } //1 googleupdate
		$a_01_3 = {55 00 70 00 64 00 61 00 74 00 65 00 20 00 53 00 65 00 72 00 76 00 69 00 63 00 65 00 } //1 Update Service
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}