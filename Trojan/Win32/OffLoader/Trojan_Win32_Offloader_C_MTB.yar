
rule Trojan_Win32_Offloader_C_MTB{
	meta:
		description = "Trojan:Win32/Offloader.C!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 02 00 "
		
	strings :
		$a_01_0 = {3a 00 2f 00 2f 00 70 00 6c 00 65 00 61 00 73 00 75 00 72 00 65 00 66 00 6c 00 79 00 2e 00 6f 00 6e 00 6c 00 69 00 6e 00 65 00 2f 00 74 00 72 00 61 00 63 00 6b 00 65 00 72 00 2f 00 74 00 68 00 61 00 6e 00 6b 00 5f 00 79 00 6f 00 75 00 2e 00 70 00 68 00 70 00 3f 00 } //02 00  ://pleasurefly.online/tracker/thank_you.php?
		$a_01_1 = {3a 00 2f 00 2f 00 6c 00 61 00 6e 00 67 00 75 00 61 00 67 00 65 00 62 00 6f 00 6e 00 65 00 2e 00 6f 00 6e 00 6c 00 69 00 6e 00 65 00 2f 00 67 00 6f 00 74 00 6f 00 2e 00 70 00 68 00 70 00 3f 00 } //01 00  ://languagebone.online/goto.php?
		$a_81_2 = {2f 73 69 6c 65 6e 74 } //00 00  /silent
	condition:
		any of ($a_*)
 
}