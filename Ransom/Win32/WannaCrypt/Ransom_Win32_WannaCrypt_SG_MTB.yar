
rule Ransom_Win32_WannaCrypt_SG_MTB{
	meta:
		description = "Ransom:Win32/WannaCrypt.SG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {65 65 65 2e 65 78 65 } //1 eee.exe
		$a_00_1 = {43 72 79 70 74 55 6e 70 72 6f 74 65 63 74 4d 65 6d 6f 72 79 } //1 CryptUnprotectMemory
		$a_02_2 = {6d 73 67 2f [0-0f] 2e 77 6e 72 79 } //2
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_02_2  & 1)*2) >=3
 
}