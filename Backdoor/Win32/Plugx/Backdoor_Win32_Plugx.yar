
rule Backdoor_Win32_Plugx{
	meta:
		description = "Backdoor:Win32/Plugx,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {4e 00 76 00 2e 00 6d 00 70 00 33 00 } //01 00 
		$a_01_1 = {68 2c 20 00 10 8d 04 45 0a 30 00 10 50 ff 15 04 20 00 10 6a 40 68 00 10 00 00 bf 00 00 10 00 57 53 ff 15 08 20 00 10 3b c3 89 45 fc 74 41 53 53 6a 03 53 6a 01 68 00 00 00 80 56 ff 15 0c 20 00 10 83 f8 ff 74 29 53 8d 4d f8 51 57 ff 75 fc 50 ff 15 10 20 00 10 85 c0 74 15 ff 55 fc 8b 35 14 20 00 10 6a ff ff d6 6a ff ff d6 6a ff ff d6 } //00 00 
	condition:
		any of ($a_*)
 
}