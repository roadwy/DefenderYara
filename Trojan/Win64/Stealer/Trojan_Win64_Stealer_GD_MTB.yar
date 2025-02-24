
rule Trojan_Win64_Stealer_GD_MTB{
	meta:
		description = "Trojan:Win64/Stealer.GD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0e 00 0a 00 00 "
		
	strings :
		$a_01_0 = {38 38 2e 31 31 39 2e 31 36 37 2e 32 33 39 } //5 88.119.167.239
		$a_01_1 = {71 75 6c 6f 6e 67 6c 6f 6e 67 } //1 qulonglong
		$a_01_2 = {72 65 6d 6f 76 65 5f 6d 65 5f 66 72 6f 6d 5f 70 6f 6f 6c } //1 remove_me_from_pool
		$a_01_3 = {62 6f 74 32 77 6f 72 6c 64 5f 63 6f 6e 6e 65 63 74 65 64 } //1 bot2world_connected
		$a_01_4 = {62 6f 74 32 77 6f 72 6c 64 5f 72 65 61 64 79 5f 72 65 61 64 } //1 bot2world_ready_read
		$a_01_5 = {62 6f 74 32 73 65 72 76 65 72 5f 63 6f 6e 6e 65 63 74 65 64 } //1 bot2server_connected
		$a_01_6 = {62 6f 74 32 73 65 72 76 65 72 5f 72 65 61 64 79 5f 72 65 61 64 } //1 bot2server_ready_read
		$a_01_7 = {5c 53 68 65 6c 6c 5c 4f 70 65 6e 5c 43 6f 6d 6d 61 6e 64 } //1 \Shell\Open\Command
		$a_01_8 = {4b 65 79 62 6f 61 72 64 4d 6f 64 69 66 69 65 72 } //1 KeyboardModifier
		$a_01_9 = {6d 61 69 6c 74 6f } //1 mailto
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1) >=14
 
}