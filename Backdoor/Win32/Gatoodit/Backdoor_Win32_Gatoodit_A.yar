
rule Backdoor_Win32_Gatoodit_A{
	meta:
		description = "Backdoor:Win32/Gatoodit.A,SIGNATURE_TYPE_PEHSTR_EXT,05 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {c6 45 fb 01 eb 0b 46 83 fe 03 7e 05 be 01 00 00 00 80 7d fb 00 0f 84 } //2
		$a_01_1 = {8a 00 2c 31 74 0e fe c8 74 16 fe c8 74 1e fe c8 74 23 eb 23 } //2
		$a_01_2 = {62 6f 74 69 64 2e 74 78 74 } //1 botid.txt
		$a_01_3 = {75 70 64 61 74 65 2e 70 68 70 3f 69 64 3d } //1 update.php?id=
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}