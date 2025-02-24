
rule Trojan_Win32_Lummac_SD{
	meta:
		description = "Trojan:Win32/Lummac.SD,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 03 00 00 "
		
	strings :
		$a_01_0 = {32 1d 30 f9 48 77 82 5a 3c bf 73 7f dd 4f 15 75 } //5
		$a_01_1 = {00 6e 75 6c 6c 00 74 72 75 65 00 66 61 6c 73 65 00 30 31 32 33 34 35 36 37 38 39 41 42 43 44 45 46 47 48 49 4a 4b 4c 4d 4e 4f 50 51 52 53 54 55 56 57 58 59 5a } //5
		$a_01_2 = {fe dc ba 98 76 54 32 10 f0 e1 d2 c3 } //5
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*5+(#a_01_2  & 1)*5) >=15
 
}