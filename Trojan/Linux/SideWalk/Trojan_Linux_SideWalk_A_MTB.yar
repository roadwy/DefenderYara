
rule Trojan_Linux_SideWalk_A_MTB{
	meta:
		description = "Trojan:Linux/SideWalk.A!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,03 00 03 00 06 00 00 "
		
	strings :
		$a_00_0 = {57 39 67 4e 52 6d 64 46 6a 78 77 4b 51 6f 73 42 59 68 6b 59 62 75 6b 4f 32 65 6a 5a 65 76 34 6d } //1 W9gNRmdFjxwKQosBYhkYbukO2ejZev4m
		$a_00_1 = {6f 52 66 54 36 57 36 41 44 7a 51 35 47 38 6a 69 64 55 73 66 59 41 57 53 4f 49 75 49 4b 52 77 63 } //1 oRfT6W6ADzQ5G8jidUsfYAWSOIuIKRwc
		$a_00_2 = {53 43 5f 49 4e 46 4f 5f 52 45 43 45 49 56 45 5f 4d 4f 44 55 4c 45 5f 53 54 41 52 54 5f 43 4f 4d 4d 41 4e 44 } //1 SC_INFO_RECEIVE_MODULE_START_COMMAND
		$a_00_3 = {53 43 5f 49 4e 46 4f 5f 42 49 5a 5f 4d 45 53 53 41 47 45 5f 53 45 4e 44 5f 54 48 52 45 41 44 5f 42 45 47 49 4e } //1 SC_INFO_BIZ_MESSAGE_SEND_THREAD_BEGIN
		$a_00_4 = {0c 20 1b e5 08 30 9b e5 03 00 52 e1 18 00 00 aa 0c 30 1b e5 9c 20 1b e5 03 30 82 e0 00 10 d3 e5 0c 20 1b e5 08 30 1b e5 03 30 42 e0 04 20 4b e2 03 30 82 e0 88 20 53 e5 0c 30 1b e5 04 00 9b e5 03 30 80 e0 01 20 22 e0 ff 20 02 e2 00 20 c3 e5 0c 30 1b e5 01 30 83 e2 0c 30 0b e5 08 30 1b e5 3f 30 83 e2 0c 20 1b e5 03 00 52 e1 e3 ff ff da } //1
		$a_00_5 = {53 43 5f 49 4e 46 4f 5f 4e 45 54 57 4f 52 4b 5f 52 45 56 45 52 53 45 5f 54 48 52 45 41 44 5f 42 45 47 49 4e } //1 SC_INFO_NETWORK_REVERSE_THREAD_BEGIN
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1) >=3
 
}