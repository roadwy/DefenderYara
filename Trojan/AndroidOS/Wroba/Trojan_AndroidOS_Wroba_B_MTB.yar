
rule Trojan_AndroidOS_Wroba_B_MTB{
	meta:
		description = "Trojan:AndroidOS/Wroba.B!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 05 00 00 03 00 "
		
	strings :
		$a_00_0 = {63 6f 6d 2f 6e 68 36 32 30 32 30 30 36 32 39 33 2f 61 63 74 69 76 69 74 79 2f 4d 61 69 6e 41 63 74 69 76 69 74 79 } //01 00  com/nh6202006293/activity/MainActivity
		$a_00_1 = {61 48 52 30 63 44 6f 76 4c 7a 45 34 4d 69 34 78 4e 69 34 34 4e 79 34 79 4d 44 49 3d } //01 00  aHR0cDovLzE4Mi4xNi44Ny4yMDI=
		$a_00_2 = {63 6f 6e 74 65 6e 74 3a 2f 2f 63 61 6c 6c 5f 6c 6f 67 2f 63 61 6c 6c 73 } //01 00  content://call_log/calls
		$a_00_3 = {64 61 74 65 20 64 65 73 63 20 6c 69 6d 69 74 20 35 30 30 } //01 00  date desc limit 500
		$a_00_4 = {44 65 63 72 79 70 74 50 61 63 6b 65 74 50 68 6f 6e } //00 00  DecryptPacketPhon
		$a_00_5 = {5d 04 00 } //00 81 
	condition:
		any of ($a_*)
 
}