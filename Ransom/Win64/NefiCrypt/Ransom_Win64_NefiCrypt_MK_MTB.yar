
rule Ransom_Win64_NefiCrypt_MK_MTB{
	meta:
		description = "Ransom:Win64/NefiCrypt.MK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_80_0 = {47 6f 20 62 75 69 6c 64 20 49 44 3a 20 22 52 36 64 76 61 55 6b 74 67 76 32 53 6a 56 58 44 6f 4d 64 6f 2f 6b 4b 67 77 61 67 77 6f 4c 52 43 38 38 44 70 49 58 41 6d 78 2f 65 69 70 4e 71 37 5f 50 51 43 54 43 4f 68 5a 36 51 37 34 71 2f 52 48 4a 6b 43 61 4e 64 54 62 64 36 71 67 59 69 41 2d 45 43 22 } //Go build ID: "R6dvaUktgv2SjVXDoMdo/kKgwagwoLRC88DpIXAmx/eipNq7_PQCTCOhZ6Q74q/RHJkCaNdTbd6qgYiA-EC"  2
		$a_80_1 = {75 6e 72 65 61 63 68 61 62 6c 65 75 73 65 72 65 6e 76 2e 64 6c 6c } //unreachableuserenv.dll  1
		$a_80_2 = {2d 44 45 43 52 59 50 54 2e 74 78 74 } //-DECRYPT.txt  1
		$a_80_3 = {73 74 6f 70 74 68 65 77 6f 72 6c 64 } //stoptheworld  1
	condition:
		((#a_80_0  & 1)*2+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1) >=4
 
}