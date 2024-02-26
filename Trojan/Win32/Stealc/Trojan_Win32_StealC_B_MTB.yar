
rule Trojan_Win32_StealC_B_MTB{
	meta:
		description = "Trojan:Win32/StealC.B!MTB,SIGNATURE_TYPE_PEHSTR_EXT,10 00 10 00 08 00 00 02 00 "
		
	strings :
		$a_01_0 = {63 68 65 63 6b 49 4f 50 6f 72 74 20 2d 20 56 4d } //02 00  checkIOPort - VM
		$a_01_1 = {63 68 65 63 6b 54 53 53 20 2d 20 56 4d } //02 00  checkTSS - VM
		$a_01_2 = {63 68 65 63 6b 48 61 72 64 77 61 72 65 49 6e 66 6f 20 2d 20 56 4d } //02 00  checkHardwareInfo - VM
		$a_01_3 = {53 45 4c 45 43 54 20 2a 20 46 52 4f 4d } //02 00  SELECT * FROM
		$a_01_4 = {57 69 6e 33 32 5f 42 61 73 65 42 6f 61 72 64 } //02 00  Win32_BaseBoard
		$a_01_5 = {57 69 6e 33 32 5f 63 6f 6d 70 75 74 65 72 73 79 73 74 65 6d } //02 00  Win32_computersystem
		$a_01_6 = {56 4d 77 61 72 65 } //02 00  VMware
		$a_01_7 = {56 69 72 74 75 61 6c 42 6f 78 } //00 00  VirtualBox
	condition:
		any of ($a_*)
 
}