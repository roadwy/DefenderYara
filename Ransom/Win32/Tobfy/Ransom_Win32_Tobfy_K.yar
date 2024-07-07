
rule Ransom_Win32_Tobfy_K{
	meta:
		description = "Ransom:Win32/Tobfy.K,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 04 00 00 "
		
	strings :
		$a_03_0 = {68 26 80 ac c8 6a 01 e8 90 01 02 ff ff 59 59 68 90 01 04 ff d0 eb 90 01 01 68 26 80 ac c8 90 00 } //1
		$a_03_1 = {be d5 fc 4f ad bd 7e 00 aa 00 80 3d 90 01 04 4b 0f 84 90 01 02 00 00 89 3d 90 01 04 68 3b b5 52 02 6a 03 e8 90 01 02 ff ff 59 59 57 68 90 01 04 ff d0 90 00 } //1
		$a_03_2 = {be f5 72 99 3d 47 56 57 e8 90 01 02 ff ff 59 59 57 ff d0 68 90 01 04 e8 90 01 02 ff ff 90 00 } //1
		$a_03_3 = {68 5a fb 7e bf 6a 03 e8 90 01 02 ff ff 59 59 ff 75 90 01 01 ff 75 90 01 01 ff 75 90 01 01 ff 75 90 01 01 ff 75 90 01 01 ff 75 90 01 01 ff 75 90 01 01 ff 75 90 01 01 ff 75 90 01 01 ff 75 90 01 01 ff 75 90 01 01 ff 75 90 01 01 ff d0 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1) >=2
 
}