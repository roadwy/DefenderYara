
rule Trojan_BAT_Killfiles_PAHD_MTB{
	meta:
		description = "Trojan:BAT/Killfiles.PAHD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 04 00 00 "
		
	strings :
		$a_00_0 = {2f 00 63 00 20 00 64 00 65 00 6c 00 20 00 2f 00 66 00 20 00 2f 00 73 00 20 00 2f 00 71 00 20 00 43 00 3a 00 5c 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 53 00 79 00 73 00 74 00 65 00 6d 00 33 00 32 00 5c 00 2a 00 2e 00 64 00 6c 00 6c 00 } //2 /c del /f /s /q C:\Windows\System32\*.dll
		$a_01_1 = {07 25 17 58 0b 0d 09 09 1b 63 09 1e 63 60 5a 20 ff 00 00 00 5f d2 13 04 06 08 11 04 9c 00 08 17 58 0c 08 20 22 56 00 00 fe 04 13 05 11 05 2d cf } //2
		$a_01_2 = {53 79 73 74 65 6d 4b 69 6c 6c 65 72 } //1 SystemKiller
		$a_00_3 = {73 00 68 00 75 00 74 00 64 00 6f 00 77 00 6e 00 } //1 shutdown
	condition:
		((#a_00_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1+(#a_00_3  & 1)*1) >=6
 
}