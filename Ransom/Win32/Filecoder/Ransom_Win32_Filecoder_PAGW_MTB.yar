
rule Ransom_Win32_Filecoder_PAGW_MTB{
	meta:
		description = "Ransom:Win32/Filecoder.PAGW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f b6 54 04 ?? 31 d1 88 4c 04 ?? 40 83 f8 ?? 7d 09 0f b6 4c 04 ?? 72 e8 } //4
	condition:
		((#a_03_0  & 1)*4) >=4
 
}
rule Ransom_Win32_Filecoder_PAGW_MTB_2{
	meta:
		description = "Ransom:Win32/Filecoder.PAGW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 06 00 00 "
		
	strings :
		$a_01_0 = {44 65 73 6b 74 6f 70 20 77 61 6c 6c 70 61 70 65 72 20 63 68 61 6e 67 65 64 20 73 75 63 63 65 73 73 66 75 6c 6c 79 2e } //2 Desktop wallpaper changed successfully.
		$a_01_1 = {46 61 69 6c 65 64 20 74 6f 20 63 72 65 61 74 65 20 66 6c 61 73 68 20 77 69 6e 64 6f 77 2e 20 45 72 72 6f 72 20 63 6f 64 65 3a } //1 Failed to create flash window. Error code:
		$a_01_2 = {53 63 72 65 65 6e 20 66 6c 61 73 68 20 63 6f 6d 70 6c 65 74 65 2e } //1 Screen flash complete.
		$a_01_3 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e } //1 SOFTWARE\Microsoft\Windows\CurrentVersion\Run
		$a_01_4 = {46 61 69 6c 65 64 20 74 6f 20 73 65 74 20 61 75 74 6f 73 74 61 72 74 20 72 65 67 69 73 74 72 79 20 76 61 6c 75 65 2e 20 45 72 72 6f 72 20 63 6f 64 65 3a } //2 Failed to set autostart registry value. Error code:
		$a_01_5 = {25 73 2e 65 6e 63 } //2 %s.enc
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*2+(#a_01_5  & 1)*2) >=9
 
}