
rule TrojanDownloader_Win32_Doina_GSH_MTB{
	meta:
		description = "TrojanDownloader:Win32/Doina.GSH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 0b 00 00 "
		
	strings :
		$a_01_0 = {68 74 74 70 3a 2f 2f 46 69 6c 65 41 70 69 2e 67 79 61 6f 74 74 2e 74 6f 70 2f 30 30 31 2f 70 75 70 70 65 74 2e 54 78 74 } //1 http://FileApi.gyaott.top/001/puppet.Txt
		$a_01_1 = {48 74 74 70 4f 70 65 6e 52 65 71 75 65 73 74 } //1 HttpOpenRequest
		$a_01_2 = {48 74 74 70 53 65 6e 64 52 65 71 75 65 73 74 } //1 HttpSendRequest
		$a_01_3 = {56 69 72 74 75 61 6c 50 72 6f 74 65 63 74 } //1 VirtualProtect
		$a_01_4 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 } //1 VirtualAlloc
		$a_01_5 = {48 54 54 50 2f 31 2e 31 } //1 HTTP/1.1
		$a_01_6 = {48 54 54 50 2f 31 2e 30 } //1 HTTP/1.0
		$a_01_7 = {41 63 63 65 70 74 2d 4c 61 6e 67 75 61 67 65 3a 20 7a 68 2d 63 6e } //1 Accept-Language: zh-cn
		$a_01_8 = {40 68 74 74 70 73 3a 2f 2f } //1 @https://
		$a_01_9 = {69 6c 4c 65 34 6f 78 69 6c 4c 65 34 6f 78 69 6c 4c 65 34 6f 78 } //1 ilLe4oxilLe4oxilLe4ox
		$a_01_10 = {33 6f 44 4f 57 33 6f 44 4f 57 62 4e 59 62 46 37 37 64 33 38 } //1 3oDOW3oDOWbNYbF77d38
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1) >=11
 
}