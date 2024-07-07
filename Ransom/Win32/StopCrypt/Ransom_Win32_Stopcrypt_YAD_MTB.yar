
rule Ransom_Win32_Stopcrypt_YAD_MTB{
	meta:
		description = "Ransom:Win32/Stopcrypt.YAD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {6a 00 ff 15 90 01 04 8b 4c 24 14 8b 44 24 10 33 cb 33 c1 89 44 24 10 2b f0 8b 44 24 24 29 44 24 18 ff 4c 24 90 00 } //1
		$a_03_1 = {8b c6 c1 e8 05 03 44 24 90 01 01 03 cd 33 c1 8b 4c 24 90 01 01 03 ce 33 c1 2b f8 8b d7 c1 e2 04 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}