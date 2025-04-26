
rule Trojan_Win64_BumbleBee_EK_MTB{
	meta:
		description = "Trojan:Win64/BumbleBee.EK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {50 41 6f 4e 32 30 34 37 } //1 PAoN2047
		$a_01_1 = {51 5a 63 76 36 38 35 77 } //1 QZcv685w
		$a_01_2 = {43 72 65 61 74 65 54 61 73 6b } //1 CreateTask
		$a_01_3 = {4c 6f 63 6b 46 69 6c 65 } //1 LockFile
		$a_01_4 = {43 72 65 61 74 65 46 69 6c 65 57 } //1 CreateFileW
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}
rule Trojan_Win64_BumbleBee_EK_MTB_2{
	meta:
		description = "Trojan:Win64/BumbleBee.EK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {48 6e 6d 7a 44 42 39 38 33 4f 38 6c } //1 HnmzDB983O8l
		$a_01_1 = {4f 75 76 50 64 31 36 } //1 OuvPd16
		$a_01_2 = {51 72 61 33 38 39 37 } //1 Qra3897
		$a_01_3 = {43 72 65 61 74 65 46 69 6c 65 57 } //1 CreateFileW
		$a_01_4 = {56 69 72 74 75 61 6c 50 72 6f 74 65 63 74 } //1 VirtualProtect
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}
rule Trojan_Win64_BumbleBee_EK_MTB_3{
	meta:
		description = "Trojan:Win64/BumbleBee.EK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {6e 48 71 52 48 54 4b 56 61 65 } //1 nHqRHTKVae
		$a_01_1 = {43 72 65 61 74 65 46 69 6c 65 4d 61 70 70 69 6e 67 41 } //1 CreateFileMappingA
		$a_01_2 = {43 72 65 61 74 65 4e 61 6d 65 64 50 69 70 65 41 } //1 CreateNamedPipeA
		$a_01_3 = {57 61 69 74 4e 61 6d 65 64 50 69 70 65 41 } //1 WaitNamedPipeA
		$a_01_4 = {4d 61 70 56 69 65 77 4f 66 46 69 6c 65 } //1 MapViewOfFile
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}