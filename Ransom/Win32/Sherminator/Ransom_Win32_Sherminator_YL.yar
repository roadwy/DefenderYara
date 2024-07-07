
rule Ransom_Win32_Sherminator_YL{
	meta:
		description = "Ransom:Win32/Sherminator.YL,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_01_0 = {44 65 63 6f 64 65 72 2e 68 74 61 } //1 Decoder.hta
		$a_01_1 = {73 68 65 72 6d 69 6e 61 74 6f 72 2e 68 65 6c 70 40 74 75 74 61 6e 6f 74 61 2e 63 6f 6d } //1 sherminator.help@tutanota.com
		$a_01_2 = {79 6f 75 2e 68 65 6c 70 35 40 70 72 6f 74 6f 6e 6d 61 69 6c 2e 63 6f 6d } //1 you.help5@protonmail.com
		$a_01_3 = {43 3a 5c 57 49 4e 44 4f 57 53 5c 64 65 6c 6f 67 2e 62 61 74 } //1 C:\WINDOWS\delog.bat
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=3
 
}