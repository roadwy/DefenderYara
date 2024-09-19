
rule Ransom_Win32_QilinCrypt_PD_MTB{
	meta:
		description = "Ransom:Win32/QilinCrypt.PD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {4c 6f 63 61 6c 5c 52 75 73 74 42 61 63 6b 74 72 61 63 65 4d 75 74 65 78 } //1 Local\RustBacktraceMutex
		$a_03_1 = {85 c0 75 12 e8 [0-04] 85 c0 0f 84 [0-04] a3 [0-04] 68 [0-04] 6a 00 50 e8 [0-04] 85 c0 0f 84 [0-04] 31 d2 bf [0-04] bb [0-04] 89 45 [0-04] c7 45 [0-04] 00 c7 45 [0-04] 00 eb } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}