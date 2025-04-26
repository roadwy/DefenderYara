
rule Ransom_Win32_Coronalock_AR_MTB{
	meta:
		description = "Ransom:Win32/Coronalock.AR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 04 00 00 "
		
	strings :
		$a_80_0 = {5c 76 62 5c 77 69 66 69 20 68 61 63 6b 65 72 } //\vb\wifi hacker  1
		$a_80_1 = {57 61 6c 6c 70 61 70 65 72 } //Wallpaper  1
		$a_80_2 = {63 3a 5c 77 68 5c 77 68 2e 6a 70 67 } //c:\wh\wh.jpg  2
		$a_80_3 = {79 6f 75 20 61 72 65 20 69 6e 66 65 63 74 65 64 20 6f 66 20 63 6f 72 6f 6e 61 20 76 69 72 75 73 } //you are infected of corona virus  5
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*2+(#a_80_3  & 1)*5) >=8
 
}