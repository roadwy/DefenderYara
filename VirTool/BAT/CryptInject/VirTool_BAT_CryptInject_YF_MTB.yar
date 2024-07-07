
rule VirTool_BAT_CryptInject_YF_MTB{
	meta:
		description = "VirTool:BAT/CryptInject.YF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {20 eb 45 d0 04 20 e8 6f 40 fd 20 ac a9 ec a6 59 66 20 e9 32 2e b1 20 db b0 97 f6 20 04 14 a1 c2 5a 61 61 61 07 66 20 16 fd 6a c9 20 96 68 94 4e 65 20 f5 f0 3e 62 65 61 20 10 b6 69 58 65 20 55 37 28 c0 66 61 59 20 d1 65 5c 40 65 65 20 5b f5 89 cc 20 0d 4a 58 98 61 20 57 43 3a f5 20 2f a7 89 74 61 58 59 58 61 61 59 20 01 42 a8 c4 5a 20 6c 67 6d 02 66 58 20 b8 79 27 fa 66 61 65 25 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}