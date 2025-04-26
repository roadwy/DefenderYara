
rule Ransom_Win32_Winshulock_A{
	meta:
		description = "Ransom:Win32/Winshulock.A,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_03_0 = {c7 04 01 01 01 01 01 83 c1 04 3b 4d ?? 72 f1 59 58 ba 02 00 00 00 8b 45 ?? e8 ?? ?? ?? ?? 8b d8 83 fb ff 74 2f } //2
		$a_00_1 = {73 68 75 74 64 6f 77 6e 20 2d 73 20 2d 74 20 30 30 20 2d 63 20 65 72 72 6f 72 20 3e 20 6e 75 6c } //2 shutdown -s -t 00 -c error > nul
		$a_02_2 = {5c 5c 2e 5c 50 68 79 73 69 63 61 6c 44 72 69 76 65 36 [0-0c] 5c 5c 2e 5c 50 68 79 73 69 63 61 6c 44 72 69 76 65 37 } //1
		$a_01_3 = {57 69 6e 55 70 64 61 74 65 } //1 WinUpdate
	condition:
		((#a_03_0  & 1)*2+(#a_00_1  & 1)*2+(#a_02_2  & 1)*1+(#a_01_3  & 1)*1) >=5
 
}