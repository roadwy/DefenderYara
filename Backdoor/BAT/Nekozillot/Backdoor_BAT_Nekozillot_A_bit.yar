
rule Backdoor_BAT_Nekozillot_A_bit{
	meta:
		description = "Backdoor:BAT/Nekozillot.A!bit,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {5c 00 41 00 70 00 70 00 44 00 61 00 74 00 61 00 5c 00 4c 00 6f 00 63 00 61 00 6c 00 5c 00 41 00 6d 00 69 00 67 00 6f 00 5c 00 55 00 73 00 65 00 72 00 20 00 44 00 61 00 74 00 61 00 5c 00 44 00 65 00 66 00 61 00 75 00 6c 00 74 00 5c 00 48 00 69 00 73 00 74 00 6f 00 72 00 79 00 } //01 00  \AppData\Local\Amigo\User Data\Default\History
		$a_01_1 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 7a 00 69 00 6c 00 6c 00 6f 00 74 00 2e 00 6b 00 7a 00 2f 00 53 00 79 00 73 00 74 00 65 00 6d 00 2f 00 6d 00 79 00 73 00 71 00 6c 00 2f 00 75 00 73 00 65 00 72 00 73 00 2e 00 70 00 68 00 70 00 } //01 00  http://zillot.kz/System/mysql/users.php
		$a_01_2 = {72 00 65 00 67 00 73 00 65 00 74 00 61 00 75 00 74 00 6f 00 } //01 00  regsetauto
		$a_01_3 = {52 00 69 00 73 00 69 00 6e 00 67 00 46 00 6f 00 72 00 63 00 65 00 32 00 } //00 00  RisingForce2
	condition:
		any of ($a_*)
 
}