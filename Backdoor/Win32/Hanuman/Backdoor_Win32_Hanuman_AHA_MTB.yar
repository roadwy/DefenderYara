
rule Backdoor_Win32_Hanuman_AHA_MTB{
	meta:
		description = "Backdoor:Win32/Hanuman.AHA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {8d 45 f8 50 8d 45 e4 50 ff 75 f4 e8 ?? ?? ?? ?? 89 45 fc 83 f8 ff 0f 84 d4 00 00 00 ff 05 ?? 30 40 00 ff 35 ?? 30 40 00 68 25 31 40 00 68 00 20 40 00 e8 ?? ?? ?? ?? 83 c4 0c 6a 00 6a 42 68 38 30 40 00 ff 75 fc e8 } //2
		$a_01_1 = {48 61 6e 75 6d 61 6e 20 53 65 72 76 65 72 20 5b 44 4f 53 20 53 48 45 4c 4c 20 44 41 45 4d 4f 4e 5d } //1 Hanuman Server [DOS SHELL DAEMON]
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}