
rule Ransom_Win32_Chicrypt_A{
	meta:
		description = "Ransom:Win32/Chicrypt.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 08 00 00 "
		
	strings :
		$a_00_0 = {59 6f 75 20 63 61 6e 20 72 65 61 63 68 20 75 73 20 76 69 61 20 74 68 65 20 62 69 74 6d 65 73 73 61 67 65 20 61 64 64 72 65 73 73 3a } //1 You can reach us via the bitmessage address:
		$a_00_1 = {43 68 69 6d 65 72 61 } //1 Chimera
		$a_00_2 = {25 73 2e 63 72 79 70 74 } //1 %s.crypt
		$a_80_3 = {5c 59 4f 55 52 5f 46 49 4c 45 53 5f 41 52 45 5f 45 4e 43 52 59 50 54 45 44 2e 48 54 4d 4c } //\YOUR_FILES_ARE_ENCRYPTED.HTML  1
		$a_00_4 = {70 61 79 20 79 6f 75 72 20 70 72 69 76 61 74 65 20 64 61 74 61 2c 20 77 68 69 63 68 20 69 6e 63 6c 75 64 65 20 70 69 63 74 75 72 65 73 20 61 6e 64 20 76 69 64 65 6f 73 20 77 69 6c 6c 20 62 65 20 70 75 62 6c 69 73 68 65 64 20 6f 6e 20 74 68 65 20 69 6e 74 65 72 6e 65 74 } //1 pay your private data, which include pictures and videos will be published on the internet
		$a_00_5 = {59 6f 75 20 61 72 65 20 76 69 63 74 69 6d 20 6f 66 20 74 68 65 20 43 68 69 6d 65 72 61 } //1 You are victim of the Chimera
		$a_00_6 = {3c 74 69 74 6c 65 3e 43 68 69 6d 65 72 61 26 72 65 67 3b 20 52 61 6e 73 6f 6d 77 61 72 65 3c 2f 74 69 74 6c 65 3e } //1 <title>Chimera&reg; Ransomware</title>
		$a_00_7 = {53 69 65 20 77 75 72 64 65 6e 20 4f 70 66 65 72 20 64 65 72 20 43 68 69 6d 65 72 61 20 4d 61 6c 77 61 72 65 2e } //1 Sie wurden Opfer der Chimera Malware.
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_80_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1+(#a_00_7  & 1)*1) >=4
 
}