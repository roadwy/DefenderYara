
rule Ransom_Win32_CryptKeeper_A{
	meta:
		description = "Ransom:Win32/CryptKeeper.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_01_0 = {59 6f 75 72 20 4b 65 65 70 65 72 20 49 44 20 63 6f 75 6c 64 20 6e 6f 74 20 62 65 20 73 65 6e 74 2e } //1 Your Keeper ID could not be sent.
		$a_01_1 = {64 61 74 61 20 77 69 6c 6c 20 62 65 20 64 65 63 72 79 70 74 65 64 20 69 6e 20 62 61 63 6b 72 6f 75 6e 64 20 6d 6f 64 65 2e } //1 data will be decrypted in backround mode.
		$a_01_2 = {25 59 2d 25 6d 2d 25 64 20 5b 25 58 5d 00 } //1
		$a_01_3 = {2f 65 2e 70 68 70 3f 69 64 3d 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=3
 
}