
rule Ransom_Win32_Magniber_AZ_MTB{
	meta:
		description = "Ransom:Win32/Magniber.AZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,65 00 65 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {f1 d5 00 fa 4c 62 cc f4 0f 0b } //64 00 
		$a_01_1 = {41 8a 08 41 ba fe 00 00 00 32 cb 80 c3 ff 88 0a 48 ff c2 84 db 0f b6 cb 41 0f 44 ca 49 ff c0 8a d9 49 ff c9 75 da 48 83 c4 20 5b 48 ff e0 } //00 00 
		$a_00_2 = {5d 04 00 00 bf 7c 05 80 5c 2a 00 00 c0 7c 05 80 00 00 01 00 08 00 14 00 54 72 6f 6a 61 6e 3a 50 48 50 2f 53 68 65 6c 6c 21 4d 53 52 00 00 02 40 05 82 70 00 04 00 67 16 00 00 30 cb a3 d5 ba 6a 36 28 be 30 30 79 49 99 00 00 01 20 be 30 30 79 67 26 00 00 6e 65 8a 47 52 69 2f 2d 00 e0 1a e3 a6 00 00 00 } //01 10 
	condition:
		any of ($a_*)
 
}