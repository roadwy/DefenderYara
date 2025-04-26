
rule Backdoor_BAT_Tzeebot_B{
	meta:
		description = "Backdoor:BAT/Tzeebot.B,SIGNATURE_TYPE_PEHSTR_EXT,11 00 11 00 04 00 00 "
		
	strings :
		$a_01_0 = {43 68 65 63 6b 46 69 6c 65 4d 44 35 43 6f 6d 70 6c 65 74 65 64 } //1 CheckFileMD5Completed
		$a_01_1 = {67 65 74 5f 48 61 69 66 61 } //1 get_Haifa
		$a_03_2 = {06 17 58 0a 90 0a 40 00 07 7e ?? ?? 00 04 7e ?? ?? 00 04 [0-02] 6f ?? ?? 00 0a 6f ?? ?? 00 0a 8c ?? 00 00 01 28 ?? 00 00 0a 0b } //5
		$a_01_3 = {54 69 6e 79 5a 42 6f 74 } //10 TinyZBot
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*5+(#a_01_3  & 1)*10) >=17
 
}