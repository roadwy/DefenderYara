
rule Backdoor_Win32_Phdet_D{
	meta:
		description = "Backdoor:Win32/Phdet.D,SIGNATURE_TYPE_PEHSTR,03 00 03 00 06 00 00 "
		
	strings :
		$a_01_0 = {7b 46 33 35 33 32 43 45 31 2d 31 38 33 32 2d 31 31 42 31 2d 39 32 30 41 2d 32 35 30 30 30 41 32 37 36 41 35 37 7d } //1 {F3532CE1-1832-11B1-920A-25000A276A57}
		$a_01_1 = {54 68 69 73 20 73 65 72 76 69 63 65 20 64 6f 77 6e 6c 6f 61 64 69 6e 67 20 61 6e 64 20 69 6e 73 74 61 6c 6c 69 6e 67 20 57 69 6e 64 6f 77 73 20 73 65 63 75 72 69 74 79 20 75 70 64 61 74 65 73 } //1 This service downloading and installing Windows security updates
		$a_01_2 = {66 6c 6f 6f 64 } //1 flood
		$a_01_3 = {68 74 74 70 3a 2f 2f 73 6f 6d 65 68 6f 73 74 2e 6e 65 74 2f 73 74 61 74 2e 70 68 70 } //1 http://somehost.net/stat.php
		$a_01_4 = {5f 62 6f 74 2e 65 78 65 } //1 _bot.exe
		$a_01_5 = {42 6c 61 63 6b 45 6e 65 72 67 79 20 44 44 6f 53 20 42 6f 74 3b } //1 BlackEnergy DDoS Bot;
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=3
 
}