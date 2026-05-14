
rule Ransom_Win64_LockBit_PK_MTB{
	meta:
		description = "Ransom:Win64/LockBit.PK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_01_0 = {43 68 75 6f 6e 67 44 6f 6e 67 20 4c 6f 63 6b 65 } //1 ChuongDong Locke
		$a_01_1 = {52 00 65 00 61 00 64 00 4d 00 65 00 46 00 6f 00 72 00 44 00 65 00 63 00 72 00 79 00 70 00 74 00 71 00 72 00 } //3 ReadMeForDecryptqr
		$a_01_2 = {5c 00 64 00 65 00 66 00 72 00 61 00 67 00 2e 00 5c 00 73 00 76 00 63 00 68 00 6f 00 73 00 74 00 } //1 \defrag.\svchost
		$a_01_3 = {58 58 58 58 58 58 58 48 48 42 42 46 46 42 42 4e 4e 42 42 4c 4c 4c 4c } //1 XXXXXXXHHBBFFBBNNBBLLLL
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*3+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=5
 
}