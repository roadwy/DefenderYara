
rule Trojan_Win32_BHO_CP{
	meta:
		description = "Trojan:Win32/BHO.CP,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 09 00 00 "
		
	strings :
		$a_01_0 = {63 3a 5c 77 69 6e 64 6f 77 73 5c 6d 65 73 73 65 6e 67 65 72 5c 6d 65 73 73 65 6e 67 65 72 2e 65 78 65 } //1 c:\windows\messenger\messenger.exe
		$a_01_1 = {2e 36 36 36 36 2e 38 38 30 30 2e 6f 72 67 } //1 .6666.8800.org
		$a_01_2 = {73 74 61 74 2e 77 61 6d 6d 65 2e 63 6e 2f 43 38 43 2f 67 6c 2f 63 6e 7a 7a 35 63 2e 68 74 6d 6c } //1 stat.wamme.cn/C8C/gl/cnzz5c.html
		$a_01_3 = {63 61 6b 65 2e 73 75 6e 66 61 63 65 70 69 7a 7a 61 2e 63 6e 2f } //1 cake.sunfacepizza.cn/
		$a_01_4 = {38 38 38 38 38 38 2e 32 32 38 38 2e 6f 72 67 2f 45 78 65 49 6e 69 31 34 2f 4d 65 73 73 65 6e 67 65 72 4e 65 77 2e 74 78 74 } //1 888888.2288.org/ExeIni14/MessengerNew.txt
		$a_01_5 = {2e 67 61 6d 65 64 61 6e 6a 69 2e 63 6e 2f 45 78 65 49 6e 69 31 34 2f 4d 65 73 73 65 6e 67 65 72 4e 65 77 2e 74 78 74 } //1 .gamedanji.cn/ExeIni14/MessengerNew.txt
		$a_01_6 = {31 32 33 35 36 33 33 2e 33 33 32 32 2e 6f 72 67 2f 45 78 65 49 6e 69 31 34 2f 4d 65 73 73 65 6e 67 65 72 4e 65 77 2e 74 78 74 } //1 1235633.3322.org/ExeIni14/MessengerNew.txt
		$a_01_7 = {73 74 61 74 2e 77 61 6d 6d 65 2e 63 6e 2f 43 38 43 2f 67 6c 2f 63 6e 7a 7a 35 62 2e 68 74 6d 6c } //1 stat.wamme.cn/C8C/gl/cnzz5b.html
		$a_01_8 = {2f 53 74 61 72 74 2e 68 74 6d 3f 41 72 65 61 49 44 3d 4e 61 4e 26 4d 65 64 69 61 49 44 3d 35 30 30 31 31 26 41 64 4e 6f 3d 25 64 26 4f 72 69 67 69 6e 61 6c 69 74 79 49 44 3d 25 64 26 55 72 6c 3d } //1 /Start.htm?AreaID=NaN&MediaID=50011&AdNo=%d&OriginalityID=%d&Url=
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1) >=7
 
}