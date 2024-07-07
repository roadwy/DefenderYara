
rule Ransom_Win32_LockBit_ADA_MTB{
	meta:
		description = "Ransom:Win32/LockBit.ADA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,65 00 65 00 02 00 00 "
		
	strings :
		$a_01_0 = {f1 d5 00 fa 4c 62 cc f4 0f 0b } //1
		$a_03_1 = {fc 9c c9 2d 90 01 04 ac d0 41 90 01 01 1d 90 01 04 55 c9 ce 8d 76 90 01 01 4e e6 90 01 01 7b 90 01 01 be 90 01 04 8c 5d 90 01 01 43 05 90 00 } //100
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*100) >=101
 
}