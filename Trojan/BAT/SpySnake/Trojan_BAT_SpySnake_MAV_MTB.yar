
rule Trojan_BAT_SpySnake_MAV_MTB{
	meta:
		description = "Trojan:BAT/SpySnake.MAV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,10 00 10 00 07 00 00 "
		
	strings :
		$a_03_0 = {06 16 06 8e 69 6f ?? ?? ?? 0a 0d 09 8e 69 1f 10 59 8d ?? ?? ?? 01 13 04 09 1f 10 11 04 16 09 8e 69 1f 10 59 28 ?? ?? ?? 0a 11 04 03 6b 28 ?? ?? ?? 06 28 ?? ?? ?? 06 ?? ?? ?? ?? ?? 28 ?? ?? ?? 06 6f ?? ?? ?? 0a ?? ?? ?? ?? ?? 03 02 ?? ?? ?? ?? ?? 13 05 11 05 2a } //10
		$a_01_1 = {53 6e 61 6b 65 49 2e 50 72 6f 70 65 72 74 69 65 73 } //1 SnakeI.Properties
		$a_01_2 = {55 6e 68 6f 6f 6b 57 69 6e 64 6f 77 73 48 6f 6f 6b 45 78 } //1 UnhookWindowsHookEx
		$a_01_3 = {53 65 74 57 69 6e 64 6f 77 50 6f 73 } //1 SetWindowPos
		$a_01_4 = {67 65 74 5f 4b 65 79 43 6f 64 65 } //1 get_KeyCode
		$a_01_5 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
		$a_01_6 = {54 72 61 6e 73 66 6f 72 6d 46 69 6e 61 6c 42 6c 6f 63 6b } //1 TransformFinalBlock
	condition:
		((#a_03_0  & 1)*10+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=16
 
}