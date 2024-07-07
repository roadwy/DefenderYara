
rule Spyware_Win32_Coolwebsearch_J{
	meta:
		description = "Spyware:Win32/Coolwebsearch.J,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_01_0 = {43 4c 53 49 44 5c 7b 39 38 44 42 42 46 31 36 2d 43 41 34 33 2d 34 63 33 33 2d 42 45 38 30 2d 39 39 45 36 36 39 34 34 36 38 41 34 7d } //1 CLSID\{98DBBF16-CA43-4c33-BE80-99E6694468A4}
		$a_01_1 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 49 6e 74 65 72 6e 65 74 20 45 78 70 6c 6f 72 65 72 5c 56 65 6e 64 6f 72 } //1 Software\Microsoft\Internet Explorer\Vendor
		$a_01_2 = {4b 69 6c 6c 45 78 65 } //1 KillExe
		$a_01_3 = {52 41 50 44 4f 53 2e 64 6c 6c } //1 RAPDOS.dll
		$a_01_4 = {5b 49 6e 74 65 72 6e 65 74 53 68 6f 72 74 63 75 74 5d } //1 [InternetShortcut]
		$a_01_5 = {5c 72 65 67 65 64 69 74 2e 65 78 65 20 2f 73 } //1 \regedit.exe /s
		$a_01_6 = {5b 5f 74 61 73 6b 5d } //1 [_task]
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=7
 
}
rule Spyware_Win32_Coolwebsearch_J_2{
	meta:
		description = "Spyware:Win32/Coolwebsearch.J,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {7b 46 44 39 42 43 30 30 34 2d 38 33 33 31 2d 34 34 35 37 2d 42 38 33 30 2d 34 37 35 39 46 46 37 30 34 43 32 32 7d } //1 {FD9BC004-8331-4457-B830-4759FF704C22}
		$a_01_1 = {53 65 61 72 63 68 48 6f 6f 6b 2e 53 65 61 72 63 68 48 6f 6f 6b 4f 62 6a 65 63 74 2e 31 } //1 SearchHook.SearchHookObject.1
		$a_01_2 = {53 65 61 72 63 68 48 6f 6f 6b 2e 44 4c 4c } //1 SearchHook.DLL
		$a_01_3 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 77 00 77 00 77 00 2e 00 73 00 65 00 61 00 72 00 63 00 68 00 2d 00 61 00 69 00 64 00 2e 00 63 00 6f 00 6d 00 2f 00 73 00 65 00 61 00 72 00 63 00 68 00 2e 00 70 00 68 00 70 00 3f 00 71 00 71 00 3d 00 } //1 http://www.search-aid.com/search.php?qq=
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}