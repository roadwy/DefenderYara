
rule Trojan_Win32_Rotaderp_B{
	meta:
		description = "Trojan:Win32/Rotaderp.B,SIGNATURE_TYPE_CMDHSTR_EXT,02 00 02 00 03 00 00 01 00 "
		
	strings :
		$a_00_0 = {2f 00 63 00 20 00 69 00 66 00 20 00 6e 00 6f 00 74 00 20 00 25 00 63 00 6f 00 6d 00 70 00 75 00 74 00 65 00 72 00 6e 00 61 00 6d 00 65 00 25 00 20 00 3d 00 3d 00 20 00 44 00 45 00 53 00 4b 00 54 00 4f 00 50 00 2d 00 51 00 4f 00 35 00 51 00 55 00 33 00 33 00 } //01 00  /c if not %computername% == DESKTOP-QO5QU33
		$a_00_1 = {52 00 75 00 6e 00 50 00 72 00 6f 00 67 00 72 00 61 00 6d 00 } //02 00  RunProgram
		$a_00_2 = {73 00 6d 00 61 00 72 00 74 00 2d 00 73 00 6f 00 66 00 74 00 2e 00 68 00 65 00 72 00 6f 00 6b 00 75 00 61 00 70 00 70 00 2e 00 63 00 6f 00 6d 00 2f 00 73 00 65 00 74 00 75 00 70 00 } //00 00  smart-soft.herokuapp.com/setup
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Rotaderp_B_2{
	meta:
		description = "Trojan:Win32/Rotaderp.B,SIGNATURE_TYPE_PEHSTR,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_01_0 = {2f 63 20 69 66 20 6e 6f 74 20 25 63 6f 6d 70 75 74 65 72 6e 61 6d 65 25 20 3d 3d 20 44 45 53 4b 54 4f 50 2d 51 4f 35 51 55 33 33 } //00 00  /c if not %computername% == DESKTOP-QO5QU33
	condition:
		any of ($a_*)
 
}