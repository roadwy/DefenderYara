
rule Ransom_Win32_HiveCrypt_MP_MTB{
	meta:
		description = "Ransom:Win32/HiveCrypt.MP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 03 00 00 "
		
	strings :
		$a_01_0 = {57 45 58 02 57 45 58 02 57 45 58 02 57 45 58 02 57 45 58 02 57 45 58 02 57 45 58 02 57 45 58 } //1
		$a_01_1 = {88 58 14 0f b6 5c 24 6c 0f b6 ac 24 d6 04 00 00 31 eb 88 58 15 0f b6 9c 24 f9 04 00 00 0f b6 ac 24 d7 04 00 00 29 eb 88 58 16 } //1
		$a_01_2 = {0f b6 ac 24 64 02 00 00 01 eb 88 98 95 00 00 00 0f b6 9c 24 59 04 00 00 0f b6 ac 24 3e 04 00 00 31 eb 88 98 96 00 00 00 0f b6 9c 24 3d 04 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=1
 
}