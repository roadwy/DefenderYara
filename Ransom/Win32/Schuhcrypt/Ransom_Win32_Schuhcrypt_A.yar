
rule Ransom_Win32_Schuhcrypt_A{
	meta:
		description = "Ransom:Win32/Schuhcrypt.A,SIGNATURE_TYPE_PEHSTR,03 00 03 00 04 00 00 "
		
	strings :
		$a_01_0 = {53 6f 66 74 77 61 72 65 5c 4c 6f 63 6b 46 69 73 68 } //1 Software\LockFish
		$a_01_1 = {5c 66 69 6c 65 65 6e 63 72 79 70 74 2e 65 78 65 } //1 \fileencrypt.exe
		$a_01_2 = {2e 66 69 73 68 69 6e 67 } //1 .fishing
		$a_01_3 = {2f 61 64 64 2e 70 68 70 3f 70 72 76 6b 65 79 3d } //1 /add.php?prvkey=
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=3
 
}