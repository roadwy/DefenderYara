
rule Backdoor_Win32_Doerbot_A{
	meta:
		description = "Backdoor:Win32/Doerbot.A,SIGNATURE_TYPE_PEHSTR_EXT,18 00 18 00 07 00 00 05 00 "
		
	strings :
		$a_01_0 = {2e 2e 2e 49 20 41 6d 20 54 68 65 20 47 72 65 61 74 65 73 74 21 21 21 2e 2e 2e } //05 00  ...I Am The Greatest!!!...
		$a_01_1 = {56 69 63 74 6f 72 79 7a 78 } //05 00  Victoryzx
		$a_01_2 = {4a 4f 53 2d 39 37 43 46 44 38 31 35 39 43 45 } //05 00  JOS-97CFD8159CE
		$a_01_3 = {5c 44 65 73 6b 74 6f 70 5c 4a 31 39 2e 70 64 62 } //02 00  \Desktop\J19.pdb
		$a_01_4 = {00 64 65 6c 65 74 65 72 00 } //02 00 
		$a_01_5 = {00 70 75 74 65 72 00 } //02 00 
		$a_01_6 = {00 73 61 76 65 72 00 } //00 00 
		$a_00_7 = {78 c3 00 00 0f 00 } //0f 00 
	condition:
		any of ($a_*)
 
}
rule Backdoor_Win32_Doerbot_A_2{
	meta:
		description = "Backdoor:Win32/Doerbot.A,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 0a 00 00 03 00 "
		
	strings :
		$a_03_0 = {68 74 74 70 3a 2f 2f 73 75 70 65 72 76 70 6e 2e 63 6f 2e 75 6b 2f 6d 79 6c 6f 67 2f 90 02 20 2e 70 68 70 90 00 } //03 00 
		$a_01_1 = {2f 6c 61 6c 61 33 2e 70 68 70 } //02 00  /lala3.php
		$a_01_2 = {3c 66 6f 72 6d 20 6d 65 74 68 6f 64 3d 22 50 4f 53 54 22 20 61 63 74 69 6f 6e 3d } //02 00  <form method="POST" action=
		$a_01_3 = {00 63 6d 64 68 69 64 65 00 } //02 00 
		$a_01_4 = {00 50 6f 73 74 20 4c 6f 67 00 } //02 00  倀獯⁴潌g
		$a_01_5 = {00 64 65 6c 65 74 65 72 00 } //02 00 
		$a_01_6 = {00 70 75 74 65 72 00 } //02 00 
		$a_01_7 = {00 73 61 76 65 72 00 } //02 00 
		$a_01_8 = {00 68 74 74 70 70 61 74 68 73 00 } //02 00 
		$a_01_9 = {7c 50 61 79 6d 65 6e 74 20 44 6f 63 75 6d 65 6e 74 } //00 00  |Payment Document
		$a_00_10 = {80 10 00 00 54 ad } //e0 38 
	condition:
		any of ($a_*)
 
}