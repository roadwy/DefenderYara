
rule TrojanClicker_Win32_Bagoox_A{
	meta:
		description = "TrojanClicker:Win32/Bagoox.A,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 06 00 00 "
		
	strings :
		$a_01_0 = {73 65 72 76 65 72 31 2e 62 61 69 67 6f 75 35 31 2e 63 6f 6d 3a 39 39 38 38 2f 6c 69 61 6e 6a 73 2f 6c 69 61 6e 6a 73 2e 74 78 74 } //1 server1.baigou51.com:9988/lianjs/lianjs.txt
		$a_01_1 = {68 74 74 70 3a 2f 2f 73 65 72 76 65 72 31 2e 62 61 69 67 6f 75 35 31 2e 63 6f 6d 3a 38 38 36 2f 75 73 65 72 2f } //1 http://server1.baigou51.com:886/user/
		$a_01_2 = {73 79 73 74 65 6d 71 5c 73 76 63 68 6f 73 74 2e 65 78 65 } //1 systemq\svchost.exe
		$a_01_3 = {68 74 74 70 3a 2f 2f 68 6f 6d 65 74 6a 2e 77 65 62 6f 6b 2e 6e 65 74 3a 31 32 33 34 2f 74 6f 6e 67 6a 69 2e 61 73 70 3f 77 77 77 69 70 3d } //1 http://hometj.webok.net:1234/tongji.asp?wwwip=
		$a_01_4 = {5f 67 75 61 6e 67 67 61 6f 5f 70 75 62 3d } //1 _guanggao_pub=
		$a_01_5 = {64 6f 63 75 6d 65 6e 74 2e 62 6f 64 79 2e 69 6e 73 65 72 74 42 65 66 6f 72 65 28 65 2c 20 64 6f 63 75 6d 65 6e 74 2e 62 6f 64 79 2e 63 68 69 6c 64 72 65 6e 2e 69 74 65 6d 28 30 29 29 } //1 document.body.insertBefore(e, document.body.children.item(0))
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=5
 
}