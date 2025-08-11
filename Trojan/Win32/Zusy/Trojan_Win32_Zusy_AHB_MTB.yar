
rule Trojan_Win32_Zusy_AHB_MTB{
	meta:
		description = "Trojan:Win32/Zusy.AHB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_01_0 = {89 ca c1 e2 05 0f be c0 01 d0 01 c1 83 c3 01 0f b6 43 ff 84 c0 75 } //2
		$a_80_1 = {42 4b 3a 20 53 75 63 63 65 73 66 75 6c 6c 79 20 64 65 6c 65 74 65 64 20 72 65 67 69 73 74 72 79 20 6b 65 79 3a 20 48 4b 45 59 5f 4c 4f 43 41 4c 5f 4d 41 43 48 49 4e 45 5c 25 73 20 2d 20 22 25 73 } //BK: Succesfully deleted registry key: HKEY_LOCAL_MACHINE\%s - "%s  1
		$a_80_2 = {42 4b 3a 20 53 75 63 63 65 73 73 66 75 6c 6c 79 20 6b 69 6c 6c 65 64 20 50 72 6f 63 65 73 73 3a 20 25 73 20 28 50 49 44 3a 20 25 6c 64 29 } //BK: Successfully killed Process: %s (PID: %ld)  1
	condition:
		((#a_01_0  & 1)*2+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1) >=4
 
}