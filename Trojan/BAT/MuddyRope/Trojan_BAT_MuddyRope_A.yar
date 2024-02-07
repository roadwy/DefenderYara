
rule Trojan_BAT_MuddyRope_A{
	meta:
		description = "Trojan:BAT/MuddyRope.A,SIGNATURE_TYPE_PEHSTR,04 00 03 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {73 76 63 68 6f 73 74 73 2e 65 78 65 } //01 00  svchosts.exe
		$a_01_1 = {4c 00 7a 00 63 00 34 00 4c 00 6a 00 45 00 79 00 4f 00 53 00 34 00 78 00 4d 00 7a 00 6b 00 75 00 4d 00 54 00 51 00 34 00 } //01 00  Lzc4LjEyOS4xMzkuMTQ4
		$a_01_2 = {50 53 32 45 58 45 48 6f 73 74 52 61 77 55 49 } //01 00  PS2EXEHostRawUI
		$a_01_3 = {69 6b 2e 50 6f 77 65 72 53 68 65 6c 6c } //00 00  ik.PowerShell
	condition:
		any of ($a_*)
 
}