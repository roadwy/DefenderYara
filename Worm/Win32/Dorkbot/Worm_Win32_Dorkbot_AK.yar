
rule Worm_Win32_Dorkbot_AK{
	meta:
		description = "Worm:Win32/Dorkbot.AK,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b 08 50 ff 51 08 8b 45 ?? 3b c3 5b 74 06 8b 08 50 ff 51 08 c9 c3 } //1
		$a_03_1 = {6a 32 ff d6 6a 00 6a 09 53 ff 75 ?? ff d7 6a 32 ff d6 6a 02 6a 10 e8 ?? ?? ?? ?? 59 59 6a 32 ff d6 6a 00 6a 0d 53 ff 75 ?? ff d7 6a 32 ff d6 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}