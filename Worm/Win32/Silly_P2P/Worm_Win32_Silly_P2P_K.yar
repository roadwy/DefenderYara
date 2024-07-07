
rule Worm_Win32_Silly_P2P_K{
	meta:
		description = "Worm:Win32/Silly_P2P.K,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 05 00 00 "
		
	strings :
		$a_01_0 = {7c 57 69 6e 64 6f 77 73 20 4c 69 76 65 20 4d 65 73 73 65 6e 67 65 72 7c } //1 |Windows Live Messenger|
		$a_01_1 = {50 61 73 73 46 69 72 65 66 6f 78 } //2 PassFirefox
		$a_01_2 = {5c 44 6f 77 6e 6c 6f 61 64 73 5c 65 4d 75 6c 65 5c 49 6e 63 6f 6d 69 6e 67 5c } //2 \Downloads\eMule\Incoming\
		$a_01_3 = {5c 6b 61 7a 61 61 20 6c 69 74 65 20 6b 2b 2b 5c 6d 79 20 73 68 61 72 65 64 20 66 6f 6c 64 65 72 5c } //2 \kazaa lite k++\my shared folder\
		$a_01_4 = {53 74 61 72 74 53 70 72 65 61 64 } //4 StartSpread
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2+(#a_01_4  & 1)*4) >=11
 
}