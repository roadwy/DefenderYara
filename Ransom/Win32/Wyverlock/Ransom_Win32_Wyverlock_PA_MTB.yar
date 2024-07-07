
rule Ransom_Win32_Wyverlock_PA_MTB{
	meta:
		description = "Ransom:Win32/Wyverlock.PA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0e 00 06 00 00 "
		
	strings :
		$a_00_0 = {78 69 65 6e 76 6b 64 6f 63 } //1 xienvkdoc
		$a_00_1 = {64 65 73 6b 74 6f 70 2e 69 6e 69 } //1 desktop.ini
		$a_00_2 = {61 75 74 6f 72 75 6e 2e 69 6e 66 } //1 autorun.inf
		$a_00_3 = {54 6f 72 20 42 72 6f 77 73 65 72 } //1 Tor Browser
		$a_00_4 = {5f 52 45 41 44 5f 4d 45 5f 2e 74 78 74 } //5 _READ_ME_.txt
		$a_02_5 = {5c 77 79 76 65 72 6e 6c 6f 63 6b 65 72 5c 90 02 10 5c 77 79 76 65 72 6e 6c 6f 63 6b 65 72 2e 70 64 62 90 00 } //5
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*5+(#a_02_5  & 1)*5) >=14
 
}