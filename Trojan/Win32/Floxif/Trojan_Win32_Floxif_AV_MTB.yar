
rule Trojan_Win32_Floxif_AV_MTB{
	meta:
		description = "Trojan:Win32/Floxif.AV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,15 00 15 00 07 00 00 03 00 "
		
	strings :
		$a_81_0 = {46 62 52 6f 62 6f 74 } //03 00  FbRobot
		$a_81_1 = {2f 73 2f 73 65 65 6d 6f 72 65 62 74 79 2f 69 6e 64 65 78 32 2e 70 68 70 } //03 00  /s/seemorebty/index2.php
		$a_81_2 = {4d 49 47 4a 41 6f 47 42 41 4d 38 34 51 59 2f 65 48 4d 6a 47 58 44 44 41 6c 59 76 } //03 00  MIGJAoGBAM84QY/eHMjGXDDAlYv
		$a_81_3 = {57 65 6f 69 4a 75 30 38 68 57 37 61 35 53 51 6c 50 47 46 43 50 76 42 61 54 49 65 47 43 62 45 57 64 4d 42 70 72 78 65 71 4d 69 69 73 78 65 67 66 31 73 4c 33 41 67 4d 42 41 41 45 3d } //03 00  WeoiJu08hW7a5SQlPGFCPvBaTIeGCbEWdMBprxeqMiisxegf1sL3AgMBAAE=
		$a_81_4 = {53 6f 66 74 77 61 72 65 5c 66 66 64 72 6f 69 64 65 72 } //03 00  Software\ffdroider
		$a_81_5 = {65 6e 63 72 79 70 74 65 64 5f 6b 65 79 } //03 00  encrypted_key
		$a_81_6 = {6f 73 5f 63 72 79 70 74 } //00 00  os_crypt
	condition:
		any of ($a_*)
 
}