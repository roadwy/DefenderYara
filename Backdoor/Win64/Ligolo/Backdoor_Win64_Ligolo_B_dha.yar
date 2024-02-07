
rule Backdoor_Win64_Ligolo_B_dha{
	meta:
		description = "Backdoor:Win64/Ligolo.B!dha,SIGNATURE_TYPE_CMDHSTR_EXT,63 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {2d 00 72 00 65 00 6c 00 61 00 79 00 73 00 65 00 72 00 76 00 65 00 72 00 } //01 00  -relayserver
		$a_01_1 = {2d 00 73 00 6b 00 69 00 70 00 76 00 65 00 72 00 69 00 66 00 79 00 } //01 00  -skipverify
		$a_01_2 = {2d 00 61 00 75 00 74 00 6f 00 72 00 65 00 73 00 74 00 61 00 72 00 74 00 } //00 00  -autorestart
	condition:
		any of ($a_*)
 
}