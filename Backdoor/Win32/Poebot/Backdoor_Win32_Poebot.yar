
rule Backdoor_Win32_Poebot{
	meta:
		description = "Backdoor:Win32/Poebot,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {6a 00 ff 35 90 01 03 00 68 90 01 03 00 8d 85 a4 ee ff ff 50 e8 90 01 02 00 00 83 c4 20 83 a5 d8 ee ff ff 00 eb 0d 8b 85 d8 ee ff ff 40 89 85 d8 ee ff ff 83 bd d8 ee ff ff 0a 75 05 e8 90 00 } //01 00 
		$a_02_1 = {8d 85 a4 ee ff ff 50 e8 89 02 00 00 83 c4 20 89 bd d8 ee ff ff 83 bd d8 ee ff ff 0a 75 05 e8 90 01 02 ff ff 68 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}