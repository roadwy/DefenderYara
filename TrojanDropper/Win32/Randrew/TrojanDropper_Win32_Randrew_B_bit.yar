
rule TrojanDropper_Win32_Randrew_B_bit{
	meta:
		description = "TrojanDropper:Win32/Randrew.B!bit,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {59 33 c9 80 34 01 90 01 01 41 3b ce 76 90 00 } //01 00 
		$a_01_1 = {6e 00 65 00 74 00 73 00 68 00 20 00 61 00 64 00 76 00 66 00 69 00 72 00 65 00 77 00 61 00 6c 00 6c 00 20 00 66 00 69 00 72 00 65 00 77 00 61 00 6c 00 6c 00 20 00 61 00 64 00 64 00 20 00 72 00 75 00 6c 00 65 00 20 00 6e 00 61 00 6d 00 65 00 3d 00 22 00 25 00 73 00 22 00 20 00 64 00 69 00 72 00 3d 00 69 00 6e 00 20 00 61 00 63 00 74 00 69 00 6f 00 6e 00 3d 00 61 00 6c 00 6c 00 6f 00 77 00 20 00 70 00 72 00 6f 00 67 00 72 00 61 00 6d 00 3d 00 22 00 25 00 73 00 22 00 } //00 00  netsh advfirewall firewall add rule name="%s" dir=in action=allow program="%s"
	condition:
		any of ($a_*)
 
}