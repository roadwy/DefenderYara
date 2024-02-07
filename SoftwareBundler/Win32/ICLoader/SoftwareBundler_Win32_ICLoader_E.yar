
rule SoftwareBundler_Win32_ICLoader_E{
	meta:
		description = "SoftwareBundler:Win32/ICLoader.E,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {5c 00 68 00 74 00 74 00 70 00 5c 00 55 00 73 00 65 00 72 00 43 00 68 00 6f 00 69 00 63 00 65 00 5c 00 50 00 72 00 6f 00 67 00 49 00 64 00 4e 00 48 00 4b 00 4c 00 4d 00 5c 00 53 00 4f 00 46 00 54 00 57 00 41 00 52 00 45 00 5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 5c 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 43 00 75 00 72 00 72 00 65 00 6e 00 74 00 56 00 65 00 72 00 73 00 69 00 6f 00 6e 00 5c 00 55 00 6e 00 69 00 6e 00 73 00 74 00 61 00 6c 00 6c 00 5c 00 72 00 65 00 67 00 65 00 78 00 70 00 3a 00 2e 00 2a 00 5c 00 44 00 69 00 73 00 70 00 6c 00 61 00 79 00 4e 00 61 00 6d 00 65 00 } //01 00  \http\UserChoice\ProgIdNHKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\regexp:.*\DisplayName
		$a_01_1 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 6d 00 65 00 67 00 61 00 64 00 6f 00 77 00 6c 00 2e 00 63 00 6f 00 6d 00 2f 00 74 00 65 00 72 00 6d 00 73 00 2d 00 72 00 75 00 2e 00 68 00 74 00 6d 00 6c 00 } //00 00  http://megadowl.com/terms-ru.html
	condition:
		any of ($a_*)
 
}