
rule TrojanDownloader_Win32_Dluca_DJ{
	meta:
		description = "TrojanDownloader:Win32/Dluca.DJ,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 "
		
	strings :
		$a_01_0 = {43 48 41 54 2c 68 74 74 70 3a 2f 2f 66 72 65 65 63 68 61 74 74 61 6c 6b 2e 63 6f 6d 2f 69 6e 66 6f 2f 73 6d 73 } //1 CHAT,http://freechattalk.com/info/sms
		$a_01_1 = {53 4d 53 2c 68 74 74 70 3a 2f 2f 66 72 65 65 63 68 61 74 74 61 6c 6b 2e 63 6f 6d 2f 69 6e 66 6f 2f 73 6d 73 } //1 SMS,http://freechattalk.com/info/sms
		$a_00_2 = {43 3a 5c 50 72 6f 67 72 61 6d 20 46 69 6c 65 73 5c 43 6f 6d 6d 6f 6e 20 46 69 6c 65 73 5c 53 79 73 74 65 6d 5c 25 73 2e 65 78 65 } //1 C:\Program Files\Common Files\System\%s.exe
		$a_00_3 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 77 00 2e 00 68 00 71 00 77 00 6d 00 64 00 6a 00 65 00 6a 00 74 00 75 00 64 00 6c 00 6b 00 2d 00 64 00 66 00 6a 00 6b 00 65 00 69 00 64 00 2e 00 63 00 6f 00 6d 00 2f 00 } //1 http://w.hqwmdjejtudlk-dfjkeid.com/
		$a_00_4 = {2d 6b 69 6c 6c 20 25 73 20 25 73 20 2f 69 6e 73 74 61 6c 6c } //1 -kill %s %s /install
		$a_00_5 = {46 72 65 65 63 68 61 74 72 6f 6f 6d 63 68 61 74 2e 63 6f 6d } //1 Freechatroomchat.com
		$a_00_6 = {77 70 61 2e 61 73 64 66 6a 6b 6c 75 69 6f 70 2e 63 6f 6d } //1 wpa.asdfjkluiop.com
		$a_00_7 = {63 3a 5c 74 65 6d 70 5c 6e 6f 6e 61 6d 65 2e 65 78 65 } //1 c:\temp\noname.exe
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1+(#a_00_7  & 1)*1) >=8
 
}