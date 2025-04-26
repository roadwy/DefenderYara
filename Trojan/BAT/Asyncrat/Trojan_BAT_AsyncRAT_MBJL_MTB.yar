
rule Trojan_BAT_AsyncRAT_MBJL_MTB{
	meta:
		description = "Trojan:BAT/AsyncRAT.MBJL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {72 e1 31 06 70 a2 25 17 72 e7 31 06 70 a2 0a 06 16 9a 06 17 9a 28 ?? 00 00 0a 72 ed 31 06 70 15 16 } //1
		$a_03_1 = {72 f3 31 06 70 15 16 28 ?? 00 00 0a 0b 16 0c 2b 2d 07 08 9a 0d 06 09 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}
rule Trojan_BAT_AsyncRAT_MBJL_MTB_2{
	meta:
		description = "Trojan:BAT/AsyncRAT.MBJL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 04 00 00 "
		
	strings :
		$a_01_0 = {36 00 49 00 67 00 33 00 41 00 51 00 43 00 49 00 4e 00 77 00 45 00 41 00 68 00 72 00 5a 00 6b 00 33 00 45 00 57 00 57 00 30 00 6a 00 43 00 66 00 75 00 52 00 4a 00 47 00 39 00 54 00 52 00 52 00 31 } //10
		$a_01_1 = {36 00 49 00 67 00 31 00 41 00 51 00 43 00 49 00 4e 00 51 00 45 00 41 00 48 00 62 00 4e 00 6e 00 76 00 38 00 39 00 59 00 70 00 6e 00 64 00 42 00 49 00 59 00 2b 00 57 00 61 00 61 00 4b 00 62 00 30 } //10
		$a_01_2 = {4e 61 74 69 76 65 43 61 6c 6c 65 72 } //1 NativeCaller
		$a_01_3 = {53 68 65 6c 6c 63 6f 64 65 } //1 Shellcode
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=12
 
}