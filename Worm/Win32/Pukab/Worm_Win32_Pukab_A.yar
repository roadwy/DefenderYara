
rule Worm_Win32_Pukab_A{
	meta:
		description = "Worm:Win32/Pukab.A,SIGNATURE_TYPE_PEHSTR_EXT,05 00 04 00 07 00 00 "
		
	strings :
		$a_01_0 = {6a 5a 6a 00 8d 85 2a fe ff ff 50 e8 } //1
		$a_01_1 = {63 6f 6e 66 62 63 6b 70 } //2 confbckp
		$a_01_2 = {73 63 72 65 65 6e 2e 6a 70 67 00 } //1
		$a_01_3 = {6e 71 2e 73 79 74 65 73 2e 6e 65 74 2f 70 2f } //1 nq.sytes.net/p/
		$a_01_4 = {72 75 6e 2e 70 68 70 00 } //1
		$a_01_5 = {75 73 65 72 61 6e 64 70 63 3d 25 73 26 61 64 6d 69 6e 3d 25 73 26 6f 73 3d 25 73 26 68 77 69 64 3d 25 73 26 6f 77 6e 65 72 69 64 3d 25 73 26 76 65 72 73 69 6f 6e 3d 25 73 } //1 userandpc=%s&admin=%s&os=%s&hwid=%s&ownerid=%s&version=%s
		$a_01_6 = {73 79 73 74 65 6d 2e 6c 68 6f } //1 system.lho
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=4
 
}