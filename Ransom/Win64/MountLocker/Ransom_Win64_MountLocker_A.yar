
rule Ransom_Win64_MountLocker_A{
	meta:
		description = "Ransom:Win64/MountLocker.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {49 8b df 48 8b d7 48 85 c9 74 90 01 01 4c 8b c1 4c 2b c7 8a 02 41 88 04 10 49 03 d6 49 2b de 75 90 01 01 49 03 cf 48 8d 1d 90 01 04 33 d2 0f b6 44 15 97 48 c1 e8 04 8a 84 18 90 01 04 88 01 49 03 ce 0f b6 44 15 97 49 03 d6 83 e0 0f 8a 84 18 90 01 04 88 01 49 03 ce 48 83 fa 10 72 90 01 01 48 8b 90 01 05 48 8d 15 90 01 04 ff 15 90 00 } //1
		$a_00_1 = {25 43 4c 49 45 4e 54 5f 49 44 25 } //1 %CLIENT_ID%
	condition:
		((#a_03_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}