
rule Ransom_Win32_CryaklCrypt_PC_MTB{
	meta:
		description = "Ransom:Win32/CryaklCrypt.PC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_01_0 = {64 65 63 72 79 70 74 20 66 69 6c 65 73 3f 20 77 72 69 74 65 20 68 65 72 65 20 33 33 33 35 37 39 39 40 70 72 6f 74 6f 6e 6d 61 69 6c 2e 63 6f 6d } //1 decrypt files? write here 3335799@protonmail.com
		$a_01_1 = {45 6e 63 72 79 70 74 65 64 20 66 69 6c 65 73 3a } //1 Encrypted files:
		$a_01_2 = {52 00 45 00 41 00 44 00 4d 00 45 00 2e 00 74 00 78 00 74 00 } //1 README.txt
		$a_01_3 = {6c 6f 67 3a 64 61 74 3a 62 6d 70 3a 70 6e 67 3a 62 61 74 3a 65 78 65 3a 63 6f 6d 3a 62 69 6e 3a } //1 log:dat:bmp:png:bat:exe:com:bin:
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=3
 
}