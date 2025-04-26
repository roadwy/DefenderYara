
rule Ransom_Win32_Denisca_A{
	meta:
		description = "Ransom:Win32/Denisca.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_01_0 = {44 65 6e 69 73 6b 61 } //1 Deniska
		$a_01_1 = {5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e } //1 \Microsoft\Windows\CurrentVersion\Run
		$a_03_2 = {68 26 80 ac c8 6a 01 8b f0 e8 ?? ?? ?? ?? 83 c4 0c 56 ff d0 } //1
		$a_01_3 = {8a 01 3c 61 7c 15 3c 7a 7f 11 0f be c0 83 e8 54 6a 1a 99 5f f7 ff 80 c2 61 eb 17 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1+(#a_01_3  & 1)*1) >=3
 
}