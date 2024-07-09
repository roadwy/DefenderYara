
rule Trojan_Win32_Zenpak_CAS_MTB{
	meta:
		description = "Trojan:Win32/Zenpak.CAS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {8b 44 24 04 8a 4c 24 08 30 08 c3 } //1
		$a_03_1 = {0f b6 c0 50 8d 0c 37 51 e8 ?? ff ff ff 83 c4 08 83 ee 01 79 } //1
		$a_01_2 = {78 61 62 69 6b 75 67 69 6b 69 6a 61 62 65 73 6f 67 75 74 75 79 6f 7a 75 20 6b 6f 6e 69 70 69 68 6f 77 75 73 6f 20 63 65 67 75 74 6f 73 69 78 75 78 61 63 6f 6a 6f 66 6f 64 61 67 6f 6c 75 68 69 74 6f 6b 69 68 6f 20 6e 69 7a 65 7a 69 67 65 73 6f 6a 65 } //1 xabikugikijabesogutuyozu konipihowuso cegutosixuxacojofodagoluhitokiho nizezigesoje
		$a_01_3 = {68 61 6d 6f 63 75 67 6f 72 6f 7a 6f 74 61 68 75 6a 61 6d 69 6a 75 72 75 6b 75 6b 69 79 69 } //1 hamocugorozotahujamijurukukiyi
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}