
rule Trojan_Win32_Banker_VB{
	meta:
		description = "Trojan:Win32/Banker.VB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 07 00 00 01 00 "
		
	strings :
		$a_02_0 = {2e 00 68 00 6f 00 73 00 74 00 34 00 38 00 2e 00 6e 00 65 00 74 00 2f 00 90 02 20 2f 00 74 00 6a 00 2e 00 68 00 74 00 6d 00 90 00 } //01 00 
		$a_00_1 = {2f 00 74 00 6d 00 61 00 6c 00 6c 00 5f 00 6e 00 65 00 77 00 2e 00 70 00 68 00 70 00 3f 00 70 00 69 00 64 00 3d 00 6d 00 6d 00 5f 00 } //01 00  /tmall_new.php?pid=mm_
		$a_00_2 = {26 00 63 00 6f 00 6d 00 6d 00 65 00 6e 00 64 00 3d 00 61 00 6c 00 6c 00 26 00 70 00 69 00 64 00 3d 00 6d 00 6d 00 5f 00 } //01 00  &commend=all&pid=mm_
		$a_00_3 = {2f 00 70 00 69 00 64 00 73 00 2e 00 74 00 78 00 74 00 } //01 00  /pids.txt
		$a_00_4 = {0a 00 53 63 72 69 70 74 6c 65 74 31 } //01 00 
		$a_00_5 = {26 00 74 00 61 00 62 00 3d 00 6d 00 61 00 6c 00 6c 00 00 00 } //01 00 
		$a_00_6 = {26 00 6d 00 6f 00 64 00 65 00 3d 00 38 00 36 00 00 00 } //00 00 
	condition:
		any of ($a_*)
 
}