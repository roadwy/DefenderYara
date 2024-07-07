
rule Spammer_Win32_Hedsen_B{
	meta:
		description = "Spammer:Win32/Hedsen.B,SIGNATURE_TYPE_PEHSTR,08 00 08 00 04 00 00 "
		
	strings :
		$a_01_0 = {39 34 2e 32 33 2e 34 39 2e 37 37 } //5 94.23.49.77
		$a_01_1 = {2f 61 63 74 69 6f 6e 2e 70 68 70 3f 61 63 74 69 6f 6e 3d 67 65 74 5f 72 65 64 } //1 /action.php?action=get_red
		$a_01_2 = {2f 61 63 74 69 6f 6e 2e 70 68 70 3f 61 63 74 69 6f 6e 3d 67 65 74 5f 6d 61 69 6c 73 } //1 /action.php?action=get_mails
		$a_01_3 = {4d 41 49 4c 20 46 52 4f 4d 3a 3c } //1 MAIL FROM:<
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=8
 
}