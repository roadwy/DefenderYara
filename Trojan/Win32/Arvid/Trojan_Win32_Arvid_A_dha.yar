
rule Trojan_Win32_Arvid_A_dha{
	meta:
		description = "Trojan:Win32/Arvid.A!dha,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 0b 00 00 "
		
	strings :
		$a_01_0 = {64 65 73 69 67 6e 65 72 73 2f 69 6d 67 2f 73 75 6e 6e 79 33 30 2e 68 74 6d 6c } //1 designers/img/sunny30.html
		$a_01_1 = {65 76 65 6e 74 73 2f 67 65 74 5f 74 65 6d 70 2e 70 68 70 } //1 events/get_temp.php
		$a_01_2 = {6d 69 78 65 64 77 6f 72 6b 2e 63 6f 6d } //1 mixedwork.com
		$a_01_3 = {65 76 65 6e 74 73 2f 61 64 64 5f 74 65 6d 70 2e 70 68 70 } //1 events/add_temp.php
		$a_01_4 = {6c 64 73 66 64 73 66 64 73 66 5a 58 58 77 65 6c 63 6f 6d 65 } //5 ldsfdsfdsfZXXwelcome
		$a_01_5 = {73 74 64 69 6f 2f 70 69 63 2f 31 2e 68 74 6d 6c } //1 stdio/pic/1.html
		$a_01_6 = {64 6f 2f 67 65 74 5f 74 65 6d 70 2e 70 68 70 } //1 do/get_temp.php
		$a_01_7 = {70 73 74 63 6d 65 64 69 61 2e 63 6f 6d } //2 pstcmedia.com
		$a_01_8 = {64 6f 2f 61 64 64 5f 74 65 6d 70 2e 70 68 70 } //1 do/add_temp.php
		$a_01_9 = {52 45 4d 4f 54 45 5f 55 53 45 52 3a } //1 REMOTE_USER:
		$a_01_10 = {55 73 65 72 2d 41 67 65 6e 74 3a 20 53 6b 79 70 65 } //2 User-Agent: Skype
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*5+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*2+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*2) >=8
 
}