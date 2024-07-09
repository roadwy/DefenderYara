
rule Ransom_Win32_LockBit_ADA_MTB{
	meta:
		description = "Ransom:Win32/LockBit.ADA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,65 00 65 00 02 00 00 "
		
	strings :
		$a_01_0 = {f1 d5 00 fa 4c 62 cc f4 0f 0b } //1
		$a_03_1 = {fc 9c c9 2d ?? ?? ?? ?? ac d0 41 ?? 1d ?? ?? ?? ?? 55 c9 ce 8d 76 ?? 4e e6 ?? 7b ?? be ?? ?? ?? ?? 8c 5d ?? 43 05 } //100
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*100) >=101
 
}