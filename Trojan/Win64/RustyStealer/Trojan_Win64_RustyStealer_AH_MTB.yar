
rule Trojan_Win64_RustyStealer_AH_MTB{
	meta:
		description = "Trojan:Win64/RustyStealer.AH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,3c 00 3c 00 03 00 00 "
		
	strings :
		$a_01_0 = {53 69 6d 70 6c 65 20 73 74 75 62 20 73 74 61 72 74 65 64 20 61 74 } //10 Simple stub started at
		$a_01_1 = {50 61 79 6c 6f 61 64 20 72 65 61 64 20 73 75 63 63 65 73 73 66 75 6c 6c 79 2c 20 73 69 7a 65 3a } //20 Payload read successfully, size:
		$a_01_2 = {43 3a 5c 74 65 6d 70 5c 64 65 62 75 67 5f 73 69 6d 70 6c 65 2e 74 78 74 } //30 C:\temp\debug_simple.txt
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*20+(#a_01_2  & 1)*30) >=60
 
}