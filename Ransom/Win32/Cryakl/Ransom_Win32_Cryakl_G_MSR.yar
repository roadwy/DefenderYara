
rule Ransom_Win32_Cryakl_G_MSR{
	meta:
		description = "Ransom:Win32/Cryakl.G!MSR,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {3c 64 69 76 3e 54 6f 20 64 6f 20 74 68 69 73 2c 20 70 6c 65 61 73 65 20 73 65 6e 64 20 79 6f 75 72 20 75 6e 69 71 75 65 20 49 44 20 74 6f 20 74 68 65 20 63 6f 6e 74 61 63 74 73 20 62 65 6c 6f 77 2e 3c 2f 64 69 76 3e } //1 <div>To do this, please send your unique ID to the contacts below.</div>
		$a_01_1 = {54 68 65 20 6c 6f 6e 67 65 72 20 79 6f 75 20 77 61 69 74 2c 20 74 68 65 20 68 69 67 68 65 72 20 77 69 6c 6c 20 62 65 63 6f 6d 65 20 74 68 65 20 64 65 63 72 79 70 74 69 6f 6e 20 6b 65 79 20 70 72 69 63 65 } //1 The longer you wait, the higher will become the decryption key price
		$a_01_2 = {3c 64 69 76 3e 42 65 66 6f 72 65 20 70 61 79 6d 65 6e 74 2c 20 77 65 20 63 61 6e 20 64 65 63 72 79 70 74 20 74 68 72 65 65 20 66 69 6c 65 73 20 66 6f 72 20 66 72 65 65 } //1 <div>Before payment, we can decrypt three files for free
		$a_01_3 = {3c 74 69 74 6c 65 3e 43 72 79 4c 6f 63 6b 3c 2f 74 69 74 6c 65 3e } //1 <title>CryLock</title>
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}