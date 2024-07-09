
rule Backdoor_Win32_IRCbot_gen_W{
	meta:
		description = "Backdoor:Win32/IRCbot.gen!W,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 06 00 00 "
		
	strings :
		$a_01_0 = {85 db 75 2a 83 f8 20 74 05 83 f8 05 75 20 6a 01 5b 68 98 3a 00 00 ff 15 } //1
		$a_03_1 = {8a 06 3c 41 88 45 fc 74 25 3c 42 74 21 3c 61 74 1d 3c 62 74 19 8d 45 fc 50 ff 15 ?? ?? ?? ?? 83 f8 02 75 0a } //1
		$a_01_2 = {25 73 20 25 73 20 22 22 20 22 6c 6f 6c 22 20 3a 25 73 } //1 %s %s "" "lol" :%s
		$a_01_3 = {25 73 5c 72 65 6d 6f 76 65 4d 65 25 69 25 69 25 69 25 69 2e 62 61 74 } //1 %s\removeMe%i%i%i%i.bat
		$a_00_4 = {53 48 45 4c 4c 33 32 2e 64 6c 6c 2c 34 0d 0a 61 63 74 69 6f 6e 3d 4f 70 65 6e 20 66 6f 6c 64 65 72 20 74 6f } //1
		$a_01_5 = {5c 67 6f 6f 67 6c 65 5f 63 61 63 68 65 25 73 2e 74 6d 70 } //1 \google_cache%s.tmp
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_00_4  & 1)*1+(#a_01_5  & 1)*1) >=5
 
}