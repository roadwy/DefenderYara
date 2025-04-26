
rule Trojan_Win32_Mariofev_B{
	meta:
		description = "Trojan:Win32/Mariofev.B,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_01_0 = {81 f9 a7 29 03 ca c6 44 24 0c e9 c6 44 24 0d f5 88 5c 24 0e 88 5c 24 0f 88 5c 24 10 c6 44 24 11 90 75 05 } //2
		$a_01_1 = {80 f9 c2 75 4d 80 38 90 75 48 80 78 01 90 75 42 8d 54 24 10 8d 4c 24 1c 52 6a 05 } //2
		$a_01_2 = {43 50 55 49 6e 66 6f 3a 43 6f 75 6e 74 3a 25 75 20 54 79 70 65 3a 25 75 } //1 CPUInfo:Count:%u Type:%u
		$a_01_3 = {49 6e 6a 65 63 74 20 43 6f 72 65 20 50 52 4f 43 45 53 53 20 3d 20 25 73 20 6c 6f 61 64 20 6d 6f 64 75 6c 65 20 3d 20 25 73 20 52 45 53 55 4c 54 20 3d 20 25 69 } //1 Inject Core PROCESS = %s load module = %s RESULT = %i
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=3
 
}