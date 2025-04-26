
rule Trojan_Win32_Growpia_A_MTB{
	meta:
		description = "Trojan:Win32/Growpia.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 05 00 00 "
		
	strings :
		$a_81_0 = {5c 53 6f 66 74 77 61 72 65 5c 47 72 6f 77 74 6f 70 69 61 } //1 \Software\Growtopia
		$a_81_1 = {4c 6f 63 61 6c 5c 47 72 6f 77 74 6f 70 69 61 5c 73 61 76 65 2e 64 61 74 } //1 Local\Growtopia\save.dat
		$a_81_2 = {53 61 76 65 46 6f 72 77 61 72 64 65 72 2f 73 61 76 65 2e 70 68 70 } //1 SaveForwarder/save.php
		$a_81_3 = {5c 57 69 6e 64 6f 77 73 5c 73 79 73 74 65 6d 33 32 5c 75 73 65 72 69 6e 69 74 2e 65 78 65 2c 22 90 01 02 5c 55 73 65 72 73 5c 90 02 15 5c 41 70 70 44 61 74 61 5c 4c 6f 63 61 6c 5c 90 02 25 2e 65 78 65 22 20 2d 73 } //1
		$a_81_4 = {5c 57 69 6e 64 6f 77 73 5c 73 79 73 74 65 6d 33 32 5c 65 6d 70 74 79 72 65 67 64 62 2e 64 61 74 } //1 \Windows\system32\emptyregdb.dat
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1) >=4
 
}