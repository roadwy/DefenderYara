
rule Trojan_Win32_Cosmu_RB_MTB{
	meta:
		description = "Trojan:Win32/Cosmu.RB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {4f 00 72 00 69 00 67 00 69 00 6e 00 61 00 6c 00 46 00 69 00 6c 00 65 00 6e 00 61 00 6d 00 65 00 00 00 44 00 6f 00 73 00 79 00 61 00 20 00 4b 00 6c 00 61 00 73 00 f6 00 72 00 fc 00 } //1
		$a_01_1 = {b9 0a 00 00 00 33 c0 8d 7d c8 33 db f3 ab b9 0a 00 00 00 8d 7d 80 f3 ab a1 f0 a4 47 00 89 5d c4 3b c3 89 5d c0 89 5d bc } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}