
rule Trojan_BAT_Zusy_HD_MTB{
	meta:
		description = "Trojan:BAT/Zusy.HD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,17 00 17 00 05 00 00 "
		
	strings :
		$a_01_0 = {50 52 4f 43 45 53 53 5f 43 52 45 41 54 45 5f 54 48 52 45 41 44 } //1 PROCESS_CREATE_THREAD
		$a_01_1 = {43 72 65 61 74 65 52 65 6d 6f 74 65 54 68 72 65 61 64 } //1 CreateRemoteThread
		$a_01_2 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 45 78 } //1 VirtualAllocEx
		$a_01_3 = {57 72 69 74 65 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 } //1 WriteProcessMemory
		$a_01_4 = {5a 00 58 00 68 00 77 00 62 00 47 00 39 00 79 00 5a 00 58 00 49 00 3d 00 00 } //20
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*20) >=23
 
}