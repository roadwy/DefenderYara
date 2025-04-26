
rule Trojan_Win32_XWorm_NW_MTB{
	meta:
		description = "Trojan:Win32/XWorm.NW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_01_0 = {8d 8c 24 a4 00 00 00 51 ff d6 8b 54 24 4c 8b 32 8d 4c 24 58 83 c6 34 e8 29 f6 ff ff 8b 0e 50 8b 44 24 50 50 ff d1 8b 74 24 58 3b f3 75 0a 68 03 40 00 80 e8 cd 8a 00 00 8d 4c 24 54 e8 04 f6 ff ff 8b 16 } //3
		$a_01_1 = {57 6d 69 50 72 76 53 45 2e 65 78 65 } //1 WmiPrvSE.exe
		$a_01_2 = {35 51 69 69 6c 63 63 6f 6c 35 32 58 72 72 74 68 64 32 2e 44 41 45 79 6f 72 34 4a 44 41 30 69 65 77 57 4b 45 32 } //1 5Qiilccol52Xrrthd2.DAEyor4JDA0iewWKE2
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=5
 
}