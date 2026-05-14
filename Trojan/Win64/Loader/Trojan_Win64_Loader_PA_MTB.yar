
rule Trojan_Win64_Loader_PA_MTB{
	meta:
		description = "Trojan:Win64/Loader.PA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {64 72 6f 70 5f 61 6e 64 5f 65 78 65 63 75 74 65 3a 20 63 61 6c 6c 69 6e 67 20 55 61 63 42 79 70 61 73 73 } //1 drop_and_execute: calling UacBypass
		$a_01_1 = {70 61 79 6c 6f 61 64 5f 6d 61 69 6e 3a 20 70 65 72 73 69 73 74 65 6e 63 65 3d 25 64 2c 20 72 65 73 75 6c 74 3d 25 64 } //1 payload_main: persistence=%d, result=%d
		$a_01_2 = {70 61 79 6c 6f 61 64 5f 6d 61 69 6e 3a 20 64 72 6f 70 5f 61 6e 64 5f 65 78 65 63 75 74 65 20 72 65 74 75 72 6e 65 64 20 25 } //1 payload_main: drop_and_execute returned %
		$a_01_3 = {70 61 79 6c 6f 61 64 5f 6d 61 69 6e 3a 20 64 65 63 72 79 70 74 69 6e 67 20 70 61 79 6c 6f 61 64 20 28 68 65 78 20 6c 65 6e 3d 25 } //1 payload_main: decrypting payload (hex len=%
		$a_01_4 = {70 61 79 6c 6f 61 64 5f 6d 61 69 6e 3a 20 61 6e 74 69 5f 76 6d 20 70 61 73 73 65 64 20 28 65 6e 61 62 6c 65 64 3d 25 } //1 payload_main: anti_vm passed (enabled=%
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}