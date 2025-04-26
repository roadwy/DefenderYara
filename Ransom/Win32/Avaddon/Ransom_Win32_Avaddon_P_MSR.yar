
rule Ransom_Win32_Avaddon_P_MSR{
	meta:
		description = "Ransom:Win32/Avaddon.P!MSR,SIGNATURE_TYPE_PEHSTR,04 00 04 00 06 00 00 "
		
	strings :
		$a_01_0 = {79 6f 75 72 20 66 69 6c 65 73 20 68 61 76 65 20 62 65 65 6e 20 65 6e 63 72 79 70 74 65 64 } //2 your files have been encrypted
		$a_01_1 = {2e 6f 6e 69 6f 6e } //1 .onion
		$a_01_2 = {54 6f 72 20 62 72 6f 77 73 65 72 } //1 Tor browser
		$a_01_3 = {72 65 61 64 5f 6d 65 5f 6c 6f 63 6b 2e 74 78 74 } //2 read_me_lock.txt
		$a_01_4 = {43 00 3a 00 5c 00 55 00 73 00 65 00 72 00 73 00 5c 00 6c 00 6f 00 63 00 6b 00 2e 00 74 00 78 00 74 00 } //1 C:\Users\lock.txt
		$a_01_5 = {57 00 69 00 6e 00 33 00 32 00 5f 00 53 00 68 00 61 00 64 00 6f 00 77 00 43 00 6f 00 70 00 79 00 2e 00 49 00 44 00 3d 00 27 00 25 00 73 00 27 00 } //1 Win32_ShadowCopy.ID='%s'
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*2+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=4
 
}