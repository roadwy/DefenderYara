
rule Backdoor_Win32_Kelihos_B{
	meta:
		description = "Backdoor:Win32/Kelihos.B,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_00_0 = {66 69 6e 64 5f 61 6e 64 5f 6b 69 6c 6c 5f 6f 6c 64 5f 63 6c 69 65 6e 74 73 00 } //3 楦摮慟摮歟汩彬汯彤汣敩瑮s
		$a_02_1 = {4d 49 49 42 43 41 4b 43 41 51 45 41 (74 46 2b 63 65 72 46 37 51 4c 57 67|78 61 4c 74 33 4e 6f 32 68 45 38 70) } //2
		$a_00_2 = {47 6f 6f 67 6c 65 49 6d 70 6c 00 } //1
		$a_00_3 = {73 6d 61 72 74 69 6e 64 65 78 } //1 smartindex
		$a_01_4 = {49 44 32 00 } //1 䑉2
	condition:
		((#a_00_0  & 1)*3+(#a_02_1  & 1)*2+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}