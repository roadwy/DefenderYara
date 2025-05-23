
rule Backdoor_Win32_Akbot_K{
	meta:
		description = "Backdoor:Win32/Akbot.K,SIGNATURE_TYPE_PEHSTR,0b 00 0b 00 0b 00 00 "
		
	strings :
		$a_01_0 = {43 6f 6e 66 69 67 47 55 49 20 2d 20 41 6b 42 6f 74 20 49 52 43 } //1 ConfigGUI - AkBot IRC
		$a_01_1 = {6c 69 73 74 53 45 52 56 45 52 53 } //1 listSERVERS
		$a_01_2 = {53 65 72 76 65 72 20 50 61 73 73 } //1 Server Pass
		$a_01_3 = {53 63 61 6e 20 43 68 61 6e 6e 65 6c } //1 Scan Channel
		$a_01_4 = {43 68 61 6e 6e 65 6c 20 4b 65 79 } //1 Channel Key
		$a_01_5 = {49 00 6e 00 70 00 75 00 74 00 20 00 42 00 6f 00 74 00 20 00 49 00 44 00 } //1 Input Bot ID
		$a_01_6 = {63 00 68 00 61 00 72 00 20 00 65 00 5f 00 62 00 6f 00 74 00 69 00 64 00 5b 00 } //1 char e_botid[
		$a_01_7 = {63 00 6f 00 6e 00 73 00 74 00 20 00 63 00 68 00 61 00 72 00 20 00 65 00 5f 00 70 00 6f 00 72 00 74 00 5b 00 } //1 const char e_port[
		$a_01_8 = {63 00 6f 00 6e 00 73 00 74 00 20 00 63 00 68 00 61 00 72 00 20 00 65 00 5f 00 73 00 65 00 72 00 76 00 65 00 72 00 70 00 61 00 73 00 73 00 5b 00 } //1 const char e_serverpass[
		$a_01_9 = {63 00 6f 00 6e 00 73 00 74 00 20 00 63 00 68 00 61 00 72 00 20 00 65 00 5f 00 63 00 68 00 61 00 6e 00 6e 00 65 00 6c 00 5b 00 } //1 const char e_channel[
		$a_01_10 = {63 00 6f 00 6e 00 73 00 74 00 20 00 63 00 68 00 61 00 72 00 20 00 65 00 5f 00 66 00 69 00 6c 00 65 00 6e 00 61 00 6d 00 65 00 5b 00 } //1 const char e_filename[
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1) >=11
 
}