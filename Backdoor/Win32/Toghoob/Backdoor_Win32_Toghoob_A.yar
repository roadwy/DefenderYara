
rule Backdoor_Win32_Toghoob_A{
	meta:
		description = "Backdoor:Win32/Toghoob.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {39 45 f8 73 1b 8b 45 08 03 45 fc 8b 4d f8 8a 00 32 81 ?? ?? ?? ?? 8b 4d 08 03 4d fc 88 01 eb ce } //1
		$a_03_1 = {6a 11 6a 02 6a 02 ff 15 ?? ?? ?? ?? 89 85 54 fc ff ff 83 bd 54 fc ff ff ff 75 07 33 c0 e9 51 01 00 00 } //1
		$a_01_2 = {8b 44 81 fc 0f be 00 83 f8 23 74 31 6a 21 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}