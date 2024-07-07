
rule Trojan_Win32_KillMBR_EM_MTB{
	meta:
		description = "Trojan:Win32/KillMBR.EM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,10 00 10 00 04 00 00 "
		
	strings :
		$a_00_0 = {8b 54 24 28 83 c4 04 83 fa 08 72 33 8b 4c 24 10 8d 14 55 02 00 00 00 8b c1 81 fa 00 10 00 00 72 14 8b 49 fc 83 c2 23 2b c1 83 c0 fc 83 f8 1f 0f 87 c0 } //10
		$a_81_1 = {73 74 61 72 74 20 65 72 61 73 69 6e 67 20 6c 6f 67 69 63 61 6c 20 64 72 69 76 65 } //2 start erasing logical drive
		$a_81_2 = {73 74 61 72 74 20 65 72 61 73 69 6e 67 20 73 79 73 74 65 6d 20 70 68 79 73 69 63 61 6c 20 64 72 69 76 65 } //2 start erasing system physical drive
		$a_81_3 = {43 3a 5c 50 72 6f 67 72 61 6d 44 61 74 61 5c 6c 6f 67 2e 74 78 74 } //2 C:\ProgramData\log.txt
	condition:
		((#a_00_0  & 1)*10+(#a_81_1  & 1)*2+(#a_81_2  & 1)*2+(#a_81_3  & 1)*2) >=16
 
}