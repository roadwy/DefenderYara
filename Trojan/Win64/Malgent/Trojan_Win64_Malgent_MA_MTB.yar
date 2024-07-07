
rule Trojan_Win64_Malgent_MA_MTB{
	meta:
		description = "Trojan:Win64/Malgent.MA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0e 00 05 00 00 "
		
	strings :
		$a_01_0 = {c7 fe 3d 2a be 1c 66 81 39 4d 5a 23 bc 19 6f 7f ff 3f 75 47 48 63 41 3c 48 01 c8 81 38 50 45 1c 38 8b 48 18 56 f9 0b 01 74 ed f7 ff bb 09 0d 02 } //10
		$a_01_1 = {10 10 84 bc df b5 76 0e 22 0d 10 f8 23 0f 95 c2 0f b6 d2 aa 36 ef b6 ef ff 89 15 90 1f 3d 01 b9 02 2e 83 38 9c 05 b9 c9 e8 dc 57 9a d8 9f cd 6c } //2
		$a_01_2 = {10 10 84 bc df b5 76 0e 22 0d 10 f8 23 0f 95 c2 0f b6 d2 aa 36 bb ed db fe 89 15 90 3f 0a b9 02 2e 83 38 9c 05 b9 c9 e8 fc f6 67 33 db 66 9a 08 } //2
		$a_01_3 = {f0 00 2e 02 0b 02 02 27 00 40 7f 00 00 10 00 00 00 d0 c9 00 e0 16 49 01 00 e0 c9 00 00 00 00 40 01 00 00 00 00 10 00 00 00 02 } //2
		$a_01_4 = {f0 00 2e 02 0b 02 02 28 00 50 7f 00 00 10 00 00 00 e0 c9 00 60 34 49 01 00 f0 c9 00 00 00 00 40 01 00 00 00 00 10 00 00 00 02 } //2
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2+(#a_01_4  & 1)*2) >=14
 
}