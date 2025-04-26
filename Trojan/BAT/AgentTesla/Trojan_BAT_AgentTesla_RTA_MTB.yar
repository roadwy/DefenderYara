
rule Trojan_BAT_AgentTesla_RTA_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.RTA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_80_0 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //FromBase64String  1
		$a_80_1 = {24 36 34 30 30 31 42 31 33 2d 37 30 38 35 2d 34 42 33 33 2d 38 38 34 41 2d 42 41 30 42 31 43 44 32 31 38 46 36 } //$64001B13-7085-4B33-884A-BA0B1CD218F6  1
		$a_03_2 = {08 07 93 28 ?? ?? ?? 0a 1f 21 32 11 08 07 93 28 ?? ?? ?? 0a 1f 7e fe 02 16 fe 01 2b 01 16 0d 09 2c 14 08 07 1f 21 08 07 93 1f 0e 58 1f 5e 5d 58 28 ?? ?? ?? 0a 9d 07 17 58 0b 07 06 6f ?? ?? ?? 0a fe 04 13 04 11 04 2d b7 } //1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}
rule Trojan_BAT_AgentTesla_RTA_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.RTA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,34 00 34 00 09 00 00 "
		
	strings :
		$a_80_0 = {44 65 62 75 67 67 65 72 42 72 6f 77 73 61 62 6c 65 41 74 74 72 69 62 75 74 65 } //DebuggerBrowsableAttribute  1
		$a_80_1 = {44 65 62 75 67 67 65 72 48 69 64 64 65 6e 41 74 74 72 69 62 75 74 65 } //DebuggerHiddenAttribute  1
		$a_80_2 = {53 75 70 70 72 65 73 73 49 6c 64 61 73 6d 41 74 74 72 69 62 75 74 65 } //SuppressIldasmAttribute  1
		$a_80_3 = {67 65 74 5f 4b 65 79 43 6f 64 65 } //get_KeyCode  1
		$a_80_4 = {24 64 30 32 36 33 32 34 38 2d 38 65 38 62 2d 34 66 64 34 2d 38 35 34 66 2d 66 30 66 35 38 36 61 61 39 31 39 65 } //$d0263248-8e8b-4fd4-854f-f0f586aa919e  10
		$a_80_5 = {6e 4e 49 62 67 42 54 4d 30 68 56 47 68 70 63 79 42 77 63 6d 39 6e 63 6d 46 74 49 47 4e 68 62 6d 35 76 64 43 42 69 5a 53 42 79 64 57 34 67 61 57 34 67 52 45 39 54 49 47 31 76 5a 47 55 75 44 51 30 4b 4a } //nNIbgBTM0hVGhpcyBwcm9ncmFtIGNhbm5vdCBiZSBydW4gaW4gRE9TIG1vZGUuDQ0KJ  10
		$a_80_6 = {55 33 52 68 63 6e 52 4a 62 6e 4e 30 63 6e 56 6a 64 47 6c 76 62 67 42 55 61 57 78 6c 51 58 52 30 63 6d 6c 69 64 58 52 6c 63 77 42 55 64 58 42 73 5a 57 } //U3RhcnRJbnN0cnVjdGlvbgBUaWxlQXR0cmlidXRlcwBUdXBsZW  10
		$a_80_7 = {51 61 2b 76 2b 73 44 4d 31 56 6b 5a 6e 78 4b 78 77 48 30 64 4a 64 51 67 4d 50 66 67 4b 6d 71 79 53 6c 34 56 30 77 32 78 59 44 4d 67 4b 6d 71 69 66 35 61 55 30 37 44 67 4b 6d 71 53 6b 67 78 4c 43 59 4a 66 54 2b 42 71 61 70 71 32 61 72 4e 37 6d 42 49 6f 79 71 42 71 61 70 42 4c 6d 4e } //Qa+v+sDM1VkZnxKxwH0dJdQgMPfgKmqySl4V0w2xYDMgKmqif5aU07DgKmqSkgxLCYJfT+Bqapq2arN7mBIoyqBqapBLmN  10
		$a_80_8 = {71 61 70 39 57 67 57 55 37 58 6e 75 61 6d 44 6c 45 6a 38 47 67 4b 6d 71 4b 66 30 4e 7a 38 2b 6d 7a 74 63 43 47 6e 75 } //qap9WgWU7XnuamDlEj8GgKmqKf0Nz8+mztcCGnu  10
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*10+(#a_80_5  & 1)*10+(#a_80_6  & 1)*10+(#a_80_7  & 1)*10+(#a_80_8  & 1)*10) >=52
 
}