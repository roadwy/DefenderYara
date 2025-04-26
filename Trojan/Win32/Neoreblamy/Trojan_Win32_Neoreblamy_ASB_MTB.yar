
rule Trojan_Win32_Neoreblamy_ASB_MTB{
	meta:
		description = "Trojan:Win32/Neoreblamy.ASB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 0a 00 00 "
		
	strings :
		$a_01_0 = {68 6c 66 70 43 6b 67 50 4b 55 4a 77 78 61 41 72 63 52 79 6e 5a 6e } //1 hlfpCkgPKUJwxaArcRynZn
		$a_01_1 = {70 74 45 48 68 71 44 63 75 61 69 6a 77 4b 51 41 65 65 59 67 45 6a 5a 76 68 76 66 4f } //1 ptEHhqDcuaijwKQAeeYgEjZvhvfO
		$a_01_2 = {76 59 46 4b 49 44 42 63 4b 62 47 54 55 6b 6e 6b 6b 67 4e 51 4d 44 71 6f 4f 75 70 4c 76 6f } //1 vYFKIDBcKbGTUknkkgNQMDqoOupLvo
		$a_01_3 = {78 6f 6f 42 69 70 59 4e 66 78 4c 61 6e 68 47 67 6f 48 6a 43 52 48 65 50 4c 65 47 59 52 } //1 xooBipYNfxLanhGgoHjCRHePLeGYR
		$a_01_4 = {41 56 54 58 52 55 49 4e 6d 4c 61 62 6c 78 53 6d 61 62 6e 4e 73 69 42 6a 73 6b 52 43 61 77 43 42 6f 66 } //1 AVTXRUINmLablxSmabnNsiBjskRCawCBof
		$a_01_5 = {53 53 6f 51 48 6a 64 50 6c 54 4b 65 57 55 71 4b 67 4b 68 68 77 69 45 } //1 SSoQHjdPlTKeWUqKgKhhwiE
		$a_01_6 = {6b 42 77 74 6e 6b 48 55 74 47 49 6a 6c 4c 64 79 64 7a 77 76 78 75 77 63 4d 6f 52 44 54 41 } //1 kBwtnkHUtGIjlLdydzwvxuwcMoRDTA
		$a_01_7 = {57 75 73 50 65 62 70 70 57 57 4a 51 6f 67 50 57 79 47 6a 6c 79 6f 41 61 78 70 79 4d } //1 WusPebppWWJQogPWyGjlyoAaxpyM
		$a_01_8 = {67 76 61 73 61 57 58 4c 64 70 41 44 55 77 75 75 42 66 72 62 73 79 51 76 79 57 56 52 74 58 } //1 gvasaWXLdpADUwuuBfrbsyQvyWVRtX
		$a_01_9 = {66 44 75 4f 4e 77 4c 6f 67 67 73 68 6d 44 75 79 42 53 63 4c 61 4f 77 4c 79 45 6b 54 } //1 fDuONwLoggshmDuyBScLaOwLyEkT
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1) >=5
 
}