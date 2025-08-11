
rule Trojan_Win32_Lazy_AYC_MTB{
	meta:
		description = "Trojan:Win32/Lazy.AYC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 05 00 00 "
		
	strings :
		$a_01_0 = {45 6e 63 72 79 70 74 69 6e 67 20 70 61 79 6c 6f 61 64 20 77 69 74 68 20 43 68 61 43 68 61 32 30 2b 58 4f 52 2e } //2 Encrypting payload with ChaCha20+XOR.
		$a_01_1 = {45 6e 63 72 79 70 74 65 64 20 70 61 79 6c 6f 61 64 20 73 69 7a 65 3a 20 25 75 20 62 79 74 65 73 2e } //1 Encrypted payload size: %u bytes.
		$a_01_2 = {4f 75 74 70 75 74 20 73 61 76 65 64 20 74 6f 20 70 61 63 6b 65 64 2e 65 78 65 } //1 Output saved to packed.exe
		$a_01_3 = {5c 52 65 6c 65 61 73 65 5c 62 69 67 44 61 77 67 2e 70 64 62 } //1 \Release\bigDawg.pdb
		$a_01_4 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 20 44 65 66 65 6e 64 65 72 5c 45 78 63 6c 75 73 69 6f 6e 73 5c 50 61 74 68 73 } //1 SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=6
 
}