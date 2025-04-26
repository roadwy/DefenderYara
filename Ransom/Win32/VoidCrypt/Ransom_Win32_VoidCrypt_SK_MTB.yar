
rule Ransom_Win32_VoidCrypt_SK_MTB{
	meta:
		description = "Ransom:Win32/VoidCrypt.SK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 07 00 00 "
		
	strings :
		$a_00_0 = {44 45 43 52 50 54 6f 66 66 69 63 65 40 67 6d 61 69 6c 2e 63 6f 6d } //1 DECRPToffice@gmail.com
		$a_81_1 = {5c 44 65 63 72 79 70 74 69 6f 6e 2d 49 6e 66 6f 2e 48 54 41 } //5 \Decryption-Info.HTA
		$a_01_2 = {76 73 73 61 64 6d 69 6e 20 64 65 6c 65 74 65 20 73 68 61 64 6f 77 73 20 2f 61 6c 6c } //1 vssadmin delete shadows /all
		$a_01_3 = {44 3a 5c 79 6f 5c 63 68 61 6f 73 5c 52 65 6c 65 61 73 65 5c 63 68 61 6f 73 2e 70 64 62 } //1 D:\yo\chaos\Release\chaos.pdb
		$a_01_4 = {43 3a 5c 50 72 6f 67 72 61 6d 44 61 74 61 5c 70 75 62 6b 65 79 2e 74 78 74 } //1 C:\ProgramData\pubkey.txt
		$a_01_5 = {43 3a 5c 50 72 6f 67 72 61 6d 44 61 74 61 5c 49 44 6f 2e 74 78 74 } //1 C:\ProgramData\IDo.txt
		$a_01_6 = {6e 65 74 73 68 20 66 69 72 65 77 61 6c 6c 20 73 65 74 20 6f 70 6d 6f 64 65 20 6d 6f 64 65 3d 64 69 73 61 62 6c 65 } //1 netsh firewall set opmode mode=disable
	condition:
		((#a_00_0  & 1)*1+(#a_81_1  & 1)*5+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=8
 
}