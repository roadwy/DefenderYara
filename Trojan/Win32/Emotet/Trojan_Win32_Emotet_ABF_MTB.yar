
rule Trojan_Win32_Emotet_ABF_MTB{
	meta:
		description = "Trojan:Win32/Emotet.ABF!MTB,SIGNATURE_TYPE_PEHSTR,02 00 01 00 03 00 00 "
		
	strings :
		$a_01_0 = {3e 74 68 61 77 35 67 2b 78 61 70 5e 6a 46 48 34 6e 55 6c 43 77 69 6a 35 5a 37 7a 78 4d 67 49 72 68 32 6f 2a 5a 61 25 54 66 3f } //1 >thaw5g+xap^jFH4nUlCwij5Z7zxMgIrh2o*Za%Tf?
		$a_01_1 = {1b de 9d df af c9 72 2e 35 ab 34 9d fd d7 33 60 34 ab 0a b6 4c f2 36 8c 48 58 fa 9d 58 8b d4 6d 98 26 11 d0 12 69 56 73 db dc ba 4f c7 cb 26 61 } //1
		$a_01_2 = {ba 3a 04 00 00 66 89 55 8a b8 4c 04 00 00 66 89 45 8c b9 37 04 00 00 66 89 4d 8e ba 47 04 00 00 66 89 55 90 b8 46 04 00 00 66 89 45 92 b9 3b 04 00 00 66 89 4d 94 ba 34 04 00 00 66 89 55 96 b8 51 04 00 00 66 89 45 98 b9 37 04 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=1
 
}