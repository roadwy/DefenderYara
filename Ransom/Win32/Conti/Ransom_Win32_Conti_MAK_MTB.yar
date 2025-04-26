
rule Ransom_Win32_Conti_MAK_MTB{
	meta:
		description = "Ransom:Win32/Conti.MAK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 03 00 00 "
		
	strings :
		$a_03_0 = {8a 06 8d 76 01 0f b6 c0 83 e8 [0-01] 6b c0 [0-01] 99 f7 fb 8d 42 [0-01] 99 f7 fb 88 56 ff 83 ef 01 75 } //10
		$a_80_1 = {65 78 70 61 6e 64 20 33 32 2d 62 79 74 65 20 6b } //expand 32-byte k  1
		$a_80_2 = {65 78 70 61 6e 64 20 31 36 2d 62 79 74 65 20 6b } //expand 16-byte k  1
	condition:
		((#a_03_0  & 1)*10+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1) >=12
 
}