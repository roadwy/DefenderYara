
rule Trojan_BAT_Tnega_RK_MTB{
	meta:
		description = "Trojan:BAT/Tnega.RK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_81_0 = {70 6f 77 65 72 73 68 65 6c 6c 20 77 67 65 74 20 68 74 74 70 73 3a 2f 2f 62 69 74 2e 6c 79 2f 33 75 4e 72 74 63 67 20 2d 4f 20 70 69 6e 2e 74 78 74 } //1 powershell wget https://bit.ly/3uNrtcg -O pin.txt
		$a_81_1 = {44 6f 77 6e 6c 6f 61 64 53 74 72 69 6e 67 28 27 68 74 74 70 73 3a 2f 2f 62 69 74 2e 6c 79 2f 33 75 4c 4a 37 30 36 27 29 } //1 DownloadString('https://bit.ly/3uLJ706')
		$a_81_2 = {2f 68 6f 6d 65 2f 6b 65 69 74 68 2f 62 75 69 6c 64 73 2f 6d 69 6e 67 77 2f 67 63 63 2d 39 2e 32 2e 30 2d 6d 69 6e 67 77 33 32 2d 63 72 6f 73 73 2d 6e 61 74 69 76 65 2f 6d 69 6e 67 77 33 32 2f 6c 69 62 67 63 63 } //1 /home/keith/builds/mingw/gcc-9.2.0-mingw32-cross-native/mingw32/libgcc
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1) >=3
 
}
rule Trojan_BAT_Tnega_RK_MTB_2{
	meta:
		description = "Trojan:BAT/Tnega.RK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {11 17 11 18 9a 13 0a 11 0a 72 ?? ?? ?? 70 72 ?? ?? ?? 70 72 ?? ?? ?? 70 6f ?? ?? ?? 0a 17 28 ?? ?? ?? 0a 2d 07 17 0b 38 ?? ?? ?? 00 11 0a 72 ?? ?? ?? 70 72 ?? ?? ?? 70 72 ?? ?? ?? 70 6f ?? ?? ?? 0a 19 6f ?? ?? ?? 0a 2c 70 11 0a 17 8d ?? ?? ?? 01 13 19 11 19 16 72 ?? ?? ?? 70 a2 11 19 18 17 6f ?? ?? ?? 0a 13 0b 11 0b 8e 69 18 2e 2f 72 ?? ?? ?? 70 } //1
		$a_81_1 = {4a 46 42 79 62 32 64 79 5a 58 4e 7a 55 48 4a 6c 5a 6d 56 79 5a 57 35 6a 5a 53 41 39 49 43 4a 54 61 57 78 6c 62 6e 52 73 65 55 4e 76 62 6e 52 70 62 6e 56 6c 49 67 30 4b 61 57 59 6f 4a 47 56 75 64 6a 70 51 59 58 52 6f 4c 6b 4e 76 62 6e 52 68 61 57 35 7a 4b 43 4a 71 59 58 5a 68 49 69 6b 70 65 77 30 4b 49 43 41 67 49 47 6c 6d 4b 46 } //1 JFByb2dyZXNzUHJlZmVyZW5jZSA9ICJTaWxlbnRseUNvbnRpbnVlIg0KaWYoJGVudjpQYXRoLkNvbnRhaW5zKCJqYXZhIikpew0KICAgIGlmKF
		$a_01_2 = {43 72 65 64 55 49 50 72 6f 6d 70 74 46 6f 72 43 72 65 64 65 6e 74 69 61 6c 73 } //1 CredUIPromptForCredentials
	condition:
		((#a_03_0  & 1)*1+(#a_81_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}