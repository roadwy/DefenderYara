
rule Trojan_Win32_Zenpak_MBHJ_MTB{
	meta:
		description = "Trojan:Win32/Zenpak.MBHJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {7d 02 8a 8c 32 4b 13 01 00 8b 15 e0 90 01 01 7d 02 88 0c 32 3d a8 00 00 00 75 90 02 12 50 ff d7 a1 a8 90 01 01 7d 02 46 3b f0 72 90 00 } //1
		$a_01_1 = {65 6a 65 74 20 73 61 7a 69 6d 6f 66 69 7a 75 76 61 76 61 76 61 6c 6f 76 69 73 65 63 6f 6b 69 66 69 6c 6f 73 } //1 ejet sazimofizuvavavalovisecokifilos
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}