
rule Ransom_Win32_Takabum_A{
	meta:
		description = "Ransom:Win32/Takabum.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 0a 00 00 "
		
	strings :
		$a_80_0 = {5c 42 69 6e 5c 61 32 68 6f 6f 6b 73 33 32 2e 70 64 62 } //\Bin\a2hooks32.pdb  -1
		$a_80_1 = {5c 7b 41 32 49 50 43 7d } //\{A2IPC}  -1
		$a_80_2 = {5b 61 32 68 6f 6f 6b 73 5d } //[a2hooks]  -1
		$a_80_3 = {43 69 63 4c 6f 61 64 65 72 57 6e 64 43 6c 61 73 73 } //CicLoaderWndClass  -1
		$a_80_4 = {54 65 73 74 69 6e 67 20 6b 65 79 20 22 25 73 22 20 76 61 6c 75 65 20 22 25 73 22 } //Testing key "%s" value "%s"  -1
		$a_80_5 = {6e 61 6d 65 20 3d 20 25 70 20 2d 20 6e 61 6d 65 6c 65 6e 20 3d 20 25 64 } //name = %p - namelen = %d  -1
		$a_02_6 = {5c 68 69 73 74 6f 72 79 5c [0-20] 5c 6d 6f 7a 69 6c 6c 61 5c [0-20] 5c 63 68 72 6f 6d 65 5c [0-20] 5c 74 65 6d 70 5c } //1
		$a_00_7 = {6a 66 69 66 2c 6a 70 65 2c 6a 70 65 67 2c 6a 70 67 2c 6a 73 2c 6b 64 62 2c 6b 64 63 2c 6b 66 2c 6c 61 79 6f 75 74 2c } //1 jfif,jpe,jpeg,jpg,js,kdb,kdc,kf,layout,
		$a_00_8 = {6f 74 68 65 72 20 69 6d 70 6f 72 74 61 6e 74 20 66 69 6c 65 73 20 68 61 76 65 20 62 65 65 6e 20 65 6e 63 72 79 70 74 65 64 20 77 69 74 68 20 73 74 72 6f 6e 67 65 73 74 20 65 6e 63 72 79 70 74 69 6f 6e 20 61 6e 64 20 75 6e 69 71 75 65 20 6b 65 79 } //1 other important files have been encrypted with strongest encryption and unique key
		$a_02_9 = {44 45 43 52 59 50 54 5f 49 4e 46 4f 5f [0-10] 2e 68 74 6d 6c } //2
	condition:
		((#a_80_0  & 1)*-1+(#a_80_1  & 1)*-1+(#a_80_2  & 1)*-1+(#a_80_3  & 1)*-1+(#a_80_4  & 1)*-1+(#a_80_5  & 1)*-1+(#a_02_6  & 1)*1+(#a_00_7  & 1)*1+(#a_00_8  & 1)*1+(#a_02_9  & 1)*2) >=4
 
}