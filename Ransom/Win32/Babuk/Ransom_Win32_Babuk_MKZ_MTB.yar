
rule Ransom_Win32_Babuk_MKZ_MTB{
	meta:
		description = "Ransom:Win32/Babuk.MKZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 04 00 00 "
		
	strings :
		$a_03_0 = {8b 45 88 33 44 8a 08 b9 04 00 00 00 d1 e1 8b 55 0c 89 04 0a b8 04 00 00 00 6b c8 07 8b 55 08 8a 84 0a ?? ?? ?? ?? 88 45 f6 b9 04 00 00 00 6b d1 07 8b 45 08 8b 8c 10 ?? ?? ?? ?? c1 e9 10 88 4d f5 } //5
		$a_00_1 = {61 6c 6c 20 79 6f 75 72 20 64 61 74 61 20 68 61 73 20 62 65 65 6e 20 65 6e 63 72 79 70 74 65 64 } //2 all your data has been encrypted
		$a_00_2 = {50 4c 45 41 53 45 20 52 45 41 44 20 4d 45 2e 74 78 74 } //2 PLEASE READ ME.txt
		$a_00_3 = {76 73 73 61 64 6d 69 6e 2e 65 78 65 20 64 65 6c 65 74 65 20 73 68 61 64 6f 77 73 20 2f 61 6c 6c 20 2f 71 75 69 65 74 } //2 vssadmin.exe delete shadows /all /quiet
	condition:
		((#a_03_0  & 1)*5+(#a_00_1  & 1)*2+(#a_00_2  & 1)*2+(#a_00_3  & 1)*2) >=11
 
}