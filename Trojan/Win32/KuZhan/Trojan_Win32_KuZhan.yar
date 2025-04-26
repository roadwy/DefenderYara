
rule Trojan_Win32_KuZhan{
	meta:
		description = "Trojan:Win32/KuZhan,SIGNATURE_TYPE_PEHSTR_EXT,10 00 10 00 09 00 00 "
		
	strings :
		$a_01_0 = {43 3a 5c 50 72 6f 67 72 61 6d 20 46 69 6c 65 73 5c 62 69 6e 64 5f } //2 C:\Program Files\bind_
		$a_01_1 = {5c 53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 49 6e 74 65 72 6e 65 74 20 45 78 70 6c 6f 72 65 72 5c 45 78 74 65 6e 73 69 6f 6e 73 5c 7b 31 44 39 30 31 30 36 37 2d 32 35 32 39 2d 34 41 39 42 2d 39 42 36 42 2d 37 41 31 44 42 33 41 34 34 43 42 35 7d } //3 \SOFTWARE\Microsoft\Internet Explorer\Extensions\{1D901067-2529-4A9B-9B6B-7A1DB3A44CB5}
		$a_01_2 = {5c 53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 45 78 70 6c 6f 72 65 72 5c 42 72 6f 77 73 65 72 20 48 65 6c 70 65 72 20 4f 62 6a 65 63 74 73 5c 7b 44 31 42 42 37 43 46 34 2d 34 34 36 33 2d 34 65 39 31 2d 38 38 44 37 2d 45 43 43 33 43 45 30 41 31 33 42 37 7d } //3 \SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects\{D1BB7CF4-4463-4e91-88D7-ECC3CE0A13B7}
		$a_01_3 = {43 3a 5c 50 72 6f 67 72 61 6d 20 46 69 6c 65 73 5c 6b 75 7a 68 61 6e 5c 6b 75 7a 68 61 6e 2e 64 6c 6c } //2 C:\Program Files\kuzhan\kuzhan.dll
		$a_01_4 = {73 73 73 31 2e 73 73 73 32 2e 31 } //2 sss1.sss2.1
		$a_01_5 = {43 3a 5c 50 72 6f 67 72 61 6d 20 46 69 6c 65 73 5c 43 6f 6d 6d 6f 6e 20 46 69 6c 65 73 5c 55 50 44 41 54 45 32 5c 75 70 64 61 74 65 2e 65 78 65 2e 31 } //2 C:\Program Files\Common Files\UPDATE2\update.exe.1
		$a_01_6 = {5c 53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 55 6e 69 6e 73 74 61 6c 6c 5c 49 45 2d 42 61 72 } //2 \SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\IE-Bar
		$a_01_7 = {68 74 74 70 3a 2f 2f 30 2e 38 32 32 31 31 2e 6e 65 74 2f } //3 http://0.82211.net/
		$a_00_8 = {2e 00 38 00 32 00 32 00 31 00 31 00 2e 00 6e 00 65 00 74 00 2f 00 } //5 .82211.net/
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*3+(#a_01_2  & 1)*3+(#a_01_3  & 1)*2+(#a_01_4  & 1)*2+(#a_01_5  & 1)*2+(#a_01_6  & 1)*2+(#a_01_7  & 1)*3+(#a_00_8  & 1)*5) >=16
 
}