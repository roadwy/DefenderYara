
rule DoS_Win64_ActionWipe_B_dha{
	meta:
		description = "DoS:Win64/ActionWipe.B!dha,SIGNATURE_TYPE_PEHSTR_EXT,ffffffc8 00 ffffffc8 00 02 00 00 64 00 "
		
	strings :
		$a_01_0 = {33 c0 8e d0 bc 00 7c fb 50 07 50 1f fc be 5d 7c 33 c9 41 81 f9 00 02 74 24 b4 43 b0 00 cd 13 fe } //64 00 
		$a_01_1 = {50 00 68 00 79 00 73 00 69 00 63 00 61 00 6c 00 44 00 72 00 69 00 76 00 65 00 25 00 64 00 20 00 20 00 57 00 72 00 69 00 74 00 65 00 20 00 4d 00 42 00 52 00 20 00 25 00 73 00 } //00 00  PhysicalDrive%d  Write MBR %s
	condition:
		any of ($a_*)
 
}