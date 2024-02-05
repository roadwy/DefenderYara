
rule Ransom_Win32_LockBit_ADA_MTB{
	meta:
		description = "Ransom:Win32/LockBit.ADA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,65 00 65 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {f1 d5 00 fa 4c 62 cc f4 0f 0b } //64 00 
		$a_03_1 = {fc 9c c9 2d 90 01 04 ac d0 41 90 01 01 1d 90 01 04 55 c9 ce 8d 76 90 01 01 4e e6 90 01 01 7b 90 01 01 be 90 01 04 8c 5d 90 01 01 43 05 90 00 } //00 00 
		$a_00_2 = {5d 04 00 00 f5 84 05 80 5c 34 00 00 f6 84 05 80 00 00 01 00 08 00 1e 00 54 72 6f 6a 61 6e 3a 50 6f 77 65 72 53 68 65 6c 6c 2f 46 69 6c 65 43 6f 64 65 72 2e 53 41 00 00 01 40 05 82 70 00 04 00 e7 5d 00 00 00 00 59 00 ad e6 17 d1 67 ac 1a 80 0b c7 18 80 ea ea e3 ad c7 17 c7 31 bc 3f 8f c7 05 93 17 67 } //0f ec 
	condition:
		any of ($a_*)
 
}