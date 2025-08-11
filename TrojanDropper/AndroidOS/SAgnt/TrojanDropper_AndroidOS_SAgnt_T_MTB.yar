
rule TrojanDropper_AndroidOS_SAgnt_T_MTB{
	meta:
		description = "TrojanDropper:AndroidOS/SAgnt.T!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_01_0 = {37 5f 6a 63 6c 61 73 73 50 31 30 5f 6a 6d 65 74 68 6f 64 49 44 7a 00 4a 61 76 61 5f 6b 5f 77 7a 5f 6b 30 00 5f 5f 73 74 72 63 61 74 5f 63 68 6b 00 4a 61 76 61 5f 6b 5f 77 7a 5f 6b 31 00 4a 61 76 61 5f 6b 5f 77 7a 5f 6b 33 00 4a 61 76 61 5f 6b 5f 77 7a 5f 6b 32 00 4a 61 76 61 5f 6b 5f 77 7a 5f 6f 31 00 5f 5a 4e 37 5f 4a 4e 49 45 6e 76 32 30 43 61 6c 6c 53 } //2
		$a_01_1 = {e5 93 fd 8a 6f c6 fe 8a 6f c6 da 8a 6f c6 3d 8b 6f c6 7c 14 b7 a7 78 0c de e5 3e 8b 6f c6 3f 8b 6f c6 d4 d6 b4 c6 32 91 45 0b 16 5b 0b 71 00 fe 5d c2 3f 8b 6f c6 4e 92 22 e1 6c e6 60 94 40 8b 6f c6 39 8b 6f c6 ce 2e fc 37 fa 8a 6f c6 80 8b 6f c6 b0 0b b8 0c c6 ff 28 fd 40 8b 6f c6 e3 23 82 8e d4 47 78 91 ce d6 87 0a fd 8a 6f c6 00 5f 5f 63 78 61 5f 66 69 6e 61 6c 69 7a 65 00 5f 5f 63 78 61 5f 61 74 65 78 69 74 00 5f 5f 72 65 67 69 73 74 65 72 5f } //1
		$a_01_2 = {6f 64 45 50 37 5f 6a 63 6c 61 73 73 50 31 30 5f 6a 6d 65 74 68 6f 64 49 44 7a 00 4a 61 76 61 5f 6b 5f 77 7a 5f 68 73 00 4a 61 76 61 5f 6b 5f 77 7a 5f 68 73 32 00 4a 61 76 61 5f 6b 5f 77 7a 5f 6d 30 00 66 6f 70 65 6e 00 66 77 72 69 74 65 00 66 63 6c 6f 73 65 00 4a 61 76 61 5f 6b 5f 77 7a 5f 6d 31 00 4a 61 76 61 5f 6b 5f 77 7a 5f 6d 32 00 5f 5a 4e 37 5f 4a 4e 49 45 6e 76 31 33 43 61 6c 6c } //1 摯偅強捪慬獳ㅐ弰浪瑥潨䥤穄䨀癡彡彫穷桟s慊慶歟睟彺獨2慊慶歟睟彺ね昀灯湥昀牷瑩e捦潬敳䨀癡彡彫穷浟1慊慶歟睟彺㉭开乚強乊䕉癮㌱慃汬
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=4
 
}