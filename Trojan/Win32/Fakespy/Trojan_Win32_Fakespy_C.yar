
rule Trojan_Win32_Fakespy_C{
	meta:
		description = "Trojan:Win32/Fakespy.C,SIGNATURE_TYPE_PEHSTR_EXT,05 00 04 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {2e 75 73 20 2d 20 73 74 6f 70 70 65 64 20 73 65 6e 64 69 6e 67 } //01 00  .us - stopped sending
		$a_01_1 = {3a 64 65 6c 63 79 63 6c 65 } //01 00  :delcycle
		$a_01_2 = {44 65 6c 65 74 65 20 73 70 79 77 61 72 65 } //01 00  Delete spyware
		$a_01_3 = {2f 73 65 63 75 72 65 2f 69 6e 64 65 78 5f 6e 65 77 2e 70 68 70 3f 69 64 3d } //01 00  /secure/index_new.php?id=
		$a_01_4 = {4c 69 63 65 6e 73 65 5f 69 64 } //00 00  License_id
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Fakespy_C_2{
	meta:
		description = "Trojan:Win32/Fakespy.C,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {2e 75 73 20 2d 20 73 74 6f 70 70 65 64 20 73 65 6e 64 69 6e 67 } //01 00  .us - stopped sending
		$a_01_1 = {3a 64 65 6c 63 79 63 6c 65 } //01 00  :delcycle
		$a_01_2 = {44 65 6c 65 74 65 20 73 70 79 77 61 72 65 } //01 00  Delete spyware
		$a_01_3 = {2f 73 65 63 75 72 65 2f 69 6e 64 65 78 5f 6e 65 77 2e 70 68 70 3f 69 64 3d } //01 00  /secure/index_new.php?id=
		$a_01_4 = {4c 69 63 65 6e 73 65 5f 69 64 } //00 00  License_id
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Fakespy_C_3{
	meta:
		description = "Trojan:Win32/Fakespy.C,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {69 6e 73 74 72 75 63 74 69 6f 6e 73 54 65 78 74 33 22 3e 43 6c 69 63 6b } //01 00  instructionsText3">Click
		$a_01_1 = {6a 61 76 61 73 63 72 69 70 74 3a 52 75 6e 41 6e 74 69 76 69 72 75 73 28 29 } //01 00  javascript:RunAntivirus()
		$a_01_2 = {62 6c 6f 63 6b 65 64 20 66 6f 72 65 76 65 72 2e 3c 2f 62 3e 3c 62 72 3e } //01 00  blocked forever.</b><br>
		$a_01_3 = {70 75 67 61 6c 6b 61 2e 64 6c 6c 00 44 6c 6c 43 61 6e 55 6e } //00 00 
	condition:
		any of ($a_*)
 
}