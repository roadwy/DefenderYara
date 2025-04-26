
rule Virus_Win32_Lopown_gen_A{
	meta:
		description = "Virus:Win32/Lopown.gen!A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 05 00 00 "
		
	strings :
		$a_01_0 = {bb 32 54 76 98 39 9d 88 fe ff ff 0f 84 65 02 00 00 81 bd 80 fe ff ff 50 45 00 00 0f 85 55 02 00 00 } //1
		$a_01_1 = {8d 45 c8 6a 28 50 80 4d ef c0 ff 75 fc ff 75 0c 56 e8 } //1
		$a_01_2 = {c7 45 c8 2e 76 69 72 8d 59 ff c7 45 cc 75 73 00 00 } //1
		$a_01_3 = {c7 45 ec 20 00 00 e0 6a 28 40 89 45 dc 8b 45 f4 } //1
		$a_01_4 = {ff 75 10 ff 75 0c ff 56 10 8d 45 10 6a 00 50 ff 75 18 ff 75 14 ff 75 0c } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=3
 
}