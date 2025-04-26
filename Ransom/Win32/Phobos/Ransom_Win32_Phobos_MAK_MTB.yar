
rule Ransom_Win32_Phobos_MAK_MTB{
	meta:
		description = "Ransom:Win32/Phobos.MAK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0a 00 02 00 00 "
		
	strings :
		$a_01_0 = {f1 d5 00 fa 4c 62 cc f4 0f 0b } //1
		$a_01_1 = {0f b6 11 ff 4c 24 04 33 d0 81 e2 ff 00 00 00 c1 e8 08 33 04 95 00 b0 40 00 41 83 7c 24 04 00 75 } //10
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*10) >=10
 
}