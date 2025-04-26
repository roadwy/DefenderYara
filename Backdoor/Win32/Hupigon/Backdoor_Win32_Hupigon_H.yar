
rule Backdoor_Win32_Hupigon_H{
	meta:
		description = "Backdoor:Win32/Hupigon.H,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_08_0 = {2e 33 33 32 32 2e 6f 72 67 00 } //1 ㌮㈳⸲牯g
		$a_08_1 = {25 41 4c 4c 55 53 45 52 53 50 52 4f 46 49 4c 45 25 5c 41 70 70 6c 69 63 61 74 69 6f 6e 20 44 61 74 61 5c 53 74 6f 72 6d 5c 75 70 64 61 74 65 5c 00 } //1
		$a_01_2 = {8b 4d f8 3b 4d fc 76 2e 8b 55 f8 8a 02 88 45 f4 8b 4d f8 8b 55 fc 8a 02 88 01 8b 4d f8 83 e9 01 } //1
	condition:
		((#a_08_0  & 1)*1+(#a_08_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}