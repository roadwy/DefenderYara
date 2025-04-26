
rule Trojan_Win32_Vobfus_ffhh_MTB{
	meta:
		description = "Trojan:Win32/Vobfus.ffhh!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 0a 00 00 "
		
	strings :
		$a_80_0 = {65 6d 67 6b 67 74 67 6e 6e 6d 6e 6d 6e 69 6e 69 67 74 68 6b 67 6f 67 67 67 76 6d 6b 68 69 6e 6a 67 67 6e 76 6d } //emgkgtgnnmnmninigthkgogggvmkhinjggnvm  2
		$a_80_1 = {73 77 6b 72 71 62 77 62 } //swkrqbwb  2
		$a_80_2 = {67 7a 67 67 79 66 65 77 6d 65 67 78 69 76 } //gzggyfewmegxiv  2
		$a_80_3 = {75 79 76 74 76 77 66 65 6b 64 75 } //uyvtvwfekdu  2
		$a_80_4 = {68 6a 72 68 76 6b 67 66 61 65 6a 68 79 } //hjrhvkgfaejhy  2
		$a_80_5 = {78 65 6d 70 6f 71 } //xempoq  2
		$a_80_6 = {71 6c 6f 69 6a 70 67 62 } //qloijpgb  2
		$a_80_7 = {74 63 62 74 6e 74 75 } //tcbtntu  2
		$a_80_8 = {5c 67 66 78 5c 73 68 6f 74 70 2e 62 6d 70 } //\gfx\shotp.bmp  2
		$a_80_9 = {71 74 68 71 76 70 62 69 2e 65 78 65 } //qthqvpbi.exe  2
	condition:
		((#a_80_0  & 1)*2+(#a_80_1  & 1)*2+(#a_80_2  & 1)*2+(#a_80_3  & 1)*2+(#a_80_4  & 1)*2+(#a_80_5  & 1)*2+(#a_80_6  & 1)*2+(#a_80_7  & 1)*2+(#a_80_8  & 1)*2+(#a_80_9  & 1)*2) >=20
 
}