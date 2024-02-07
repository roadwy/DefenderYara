
rule Trojan_Win32_Emotetcrypt_IN_MTB{
	meta:
		description = "Trojan:Win32/Emotetcrypt.IN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 04 00 00 01 00 "
		
	strings :
		$a_81_0 = {40 32 5e 7a 44 3c 42 69 45 25 6d 4f 56 71 6d 3c 36 6f 6c 28 47 36 5e 72 78 53 63 55 69 4a 4a 32 55 52 3f 75 52 77 54 37 41 28 4d 36 51 66 53 6f 53 24 4e 5f 73 65 52 6b 65 26 70 47 26 29 34 67 76 6f 6c 26 43 37 } //01 00  @2^zD<BiE%mOVqm<6ol(G6^rxScUiJJ2UR?uRwT7A(M6QfSoS$N_seRke&pG&)4gvol&C7
		$a_81_1 = {33 32 33 59 6d 25 49 4d 35 6c 6c 6e 4f 61 40 21 46 69 44 6e 74 73 63 66 6c 48 4f 2a 38 7a 5f 33 32 78 5a 26 76 42 46 49 59 3e 40 3c 71 33 79 } //01 00  323Ym%IM5llnOa@!FiDntscflHO*8z_32xZ&vBFIY>@<q3y
		$a_81_2 = {76 66 6e 52 52 23 37 66 52 74 63 3c 74 64 34 3f 55 2a 58 68 34 7a 6a 4b 58 45 5a 36 38 38 59 64 57 3e 4c 30 46 29 33 76 3e 44 6b 57 57 63 55 40 } //01 00  vfnRR#7fRtc<td4?U*Xh4zjKXEZ688YdW>L0F)3v>DkWWcU@
		$a_81_3 = {44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 } //00 00  DllRegisterServer
	condition:
		any of ($a_*)
 
}