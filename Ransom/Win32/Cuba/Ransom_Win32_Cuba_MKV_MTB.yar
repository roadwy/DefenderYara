
rule Ransom_Win32_Cuba_MKV_MTB{
	meta:
		description = "Ransom:Win32/Cuba.MKV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {2b f0 2b f8 8d 4d 90 01 01 03 ca 42 8a 04 0e 32 01 88 04 0f 8b 4d 10 3b d1 72 90 00 } //1
		$a_00_1 = {41 6c 6c 20 79 6f 75 72 20 66 69 6c 65 73 20 61 72 65 20 65 6e 63 72 79 70 74 65 64 } //1 All your files are encrypted
		$a_00_2 = {44 6f 20 6e 6f 74 20 72 65 6e 61 6d 65 20 65 6e 63 72 79 70 74 65 64 20 66 69 6c 65 73 2e } //1 Do not rename encrypted files.
	condition:
		((#a_03_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}