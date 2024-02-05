
rule Backdoor_Win32_Rbot_gen_H{
	meta:
		description = "Backdoor:Win32/Rbot.gen!H,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b 06 03 d8 50 8d 46 da 50 8d 85 90 01 02 ff ff 68 90 01 03 00 50 e8 90 01 03 00 8d 85 90 01 02 ff ff 57 50 8d 85 90 01 02 ff ff 50 e8 90 01 04 83 c6 3c 83 c4 1c 83 7e f8 00 75 c6 5e 90 00 } //01 00 
	condition:
		any of ($a_*)
 
}