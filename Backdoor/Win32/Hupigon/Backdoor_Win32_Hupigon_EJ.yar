
rule Backdoor_Win32_Hupigon_EJ{
	meta:
		description = "Backdoor:Win32/Hupigon.EJ,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_00_0 = {72 75 6e 64 6c 6c 33 32 2e 65 78 65 20 25 73 2c 20 53 74 61 72 74 75 70 20 25 73 00 } //01 00 
		$a_00_1 = {0d 0a 5b 25 30 32 64 2f 25 30 32 64 2f 25 64 20 25 30 32 64 3a 25 30 32 64 3a 25 30 32 64 5d 20 28 25 73 29 0d 0a } //01 00 
		$a_03_2 = {c7 45 fc ff ff ff ff e8 90 01 04 39 9d 90 01 02 ff ff 75 90 01 01 3b f3 74 0f 56 53 ff 95 90 01 02 ff ff 50 ff 95 90 01 02 ff ff 33 c0 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}