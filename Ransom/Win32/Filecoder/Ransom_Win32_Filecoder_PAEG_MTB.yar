
rule Ransom_Win32_Filecoder_PAEG_MTB{
	meta:
		description = "Ransom:Win32/Filecoder.PAEG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {8a 04 10 8b 55 f4 32 04 32 8b 55 e0 88 02 42 8b 45 f4 40 89 55 e0 89 45 f4 3b c7 72 da } //1
		$a_01_1 = {73 00 65 00 6c 00 65 00 63 00 74 00 20 00 2a 00 20 00 66 00 72 00 6f 00 6d 00 20 00 57 00 69 00 6e 00 33 00 32 00 5f 00 53 00 68 00 61 00 64 00 6f 00 77 00 43 00 6f 00 70 00 79 00 } //1 select * from Win32_ShadowCopy
		$a_01_2 = {52 00 4f 00 4f 00 54 00 5c 00 63 00 69 00 6d 00 76 00 32 00 } //1 ROOT\cimv2
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}