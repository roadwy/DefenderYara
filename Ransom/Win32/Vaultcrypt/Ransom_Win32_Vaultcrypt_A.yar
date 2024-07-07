
rule Ransom_Win32_Vaultcrypt_A{
	meta:
		description = "Ransom:Win32/Vaultcrypt.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 07 00 00 "
		
	strings :
		$a_01_0 = {73 75 62 20 57 69 6e 64 6f 77 5f 4f 6e 6c 6f 61 64 } //1 sub Window_Onload
		$a_01_1 = {20 56 41 55 4c 54 2e 4b 45 59 3c 62 72 3e } //1  VAULT.KEY<br>
		$a_01_2 = {30 31 46 4e 53 48 2d 25 64 } //1 01FNSH-%d
		$a_01_3 = {46 48 41 53 48 2d 25 64 } //1 FHASH-%d
		$a_01_4 = {2d 2d 2d 2d 2d 42 45 47 49 4e 20 50 55 42 4c 49 43 20 4b 45 59 2d 2d 2d 2d 2d } //1 -----BEGIN PUBLIC KEY-----
		$a_01_5 = {3d 22 68 74 74 70 3a 2f 2f 64 69 73 74 2e 74 6f 72 70 72 6f 6a 65 63 74 2e 6f 72 67 2f 74 6f 72 62 72 6f 77 73 65 72 } //1 ="http://dist.torproject.org/torbrowser
		$a_01_6 = {3d 22 68 74 74 70 3a 2f 2f 74 6f 72 73 63 72 65 65 6e 2e 6f 72 67 } //1 ="http://torscreen.org
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=2
 
}