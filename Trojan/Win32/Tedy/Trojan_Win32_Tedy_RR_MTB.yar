
rule Trojan_Win32_Tedy_RR_MTB{
	meta:
		description = "Trojan:Win32/Tedy.RR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {88 d6 80 c6 9f 80 fe 1a 0f 92 c6 43 40 c0 e6 05 30 d6 88 31 41 4f } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Tedy_RR_MTB_2{
	meta:
		description = "Trojan:Win32/Tedy.RR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {8b 4c 24 68 30 08 8b 44 24 38 40 3b c3 1b d2 23 d0 85 ff 7e 07 8a 44 24 72 88 06 } //1
		$a_00_1 = {28 00 38 00 45 00 32 00 33 00 48 00 37 00 4c 00 4d 00 3d 00 3d 00 4e 00 51 00 3c 00 41 00 45 00 45 00 55 00 44 00 4a 00 48 00 57 00 4b 00 57 00 5a 00 5a 00 4a 00 50 00 50 00 54 00 63 00 62 00 64 00 55 00 59 00 5a 00 64 00 56 00 57 00 67 00 6a 00 } //1 (8E23H7LM==NQ<AEEUDJHWKWZZJPPTcbdUYZdVWgj
		$a_01_2 = {43 3a 5c 62 75 69 6c 64 6d 61 63 68 69 6e 65 5c 54 65 6d 70 5c 73 72 63 4e 34 4d 5f 34 78 5c 57 69 6e 64 6f 77 73 5c 4f 75 74 5f 32 30 31 33 5c 78 38 36 5c 52 65 6c 65 61 73 65 5c 44 4c 43 4c 5c 44 4c 43 4c 2e 70 64 62 } //1 C:\buildmachine\Temp\srcN4M_4x\Windows\Out_2013\x86\Release\DLCL\DLCL.pdb
		$a_01_3 = {44 4c 43 4c 2e 65 78 65 } //1 DLCL.exe
	condition:
		((#a_01_0  & 1)*1+(#a_00_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}