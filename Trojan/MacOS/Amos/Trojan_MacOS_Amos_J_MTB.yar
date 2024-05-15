
rule Trojan_MacOS_Amos_J_MTB{
	meta:
		description = "Trojan:MacOS/Amos.J!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,0b 00 0b 00 06 00 00 05 00 "
		
	strings :
		$a_00_0 = {c0 00 00 f0 00 20 0c 91 7c f9 ff 97 e1 03 00 aa f5 83 00 91 e0 83 00 91 cc 3b 00 94 e8 df 40 39 09 1d 00 13 3f 01 00 71 ea 27 42 a9 28 b1 88 9a 40 b1 95 9a 1f 15 00 f1 01 01 00 54 08 00 40 b9 08 01 14 4a 09 10 40 39 4a 0a 80 52 29 01 0a 4a 08 01 09 2a e8 00 00 34 } //05 00 
		$a_00_1 = {93 0d 00 b4 b4 48 8a 52 54 ea a9 72 c0 00 00 f0 00 38 0d 91 98 f9 ff 97 e1 03 00 aa f5 03 01 91 e0 03 01 91 e8 3b 00 94 e8 5f 41 39 09 1d 00 13 3f 01 00 71 ea 27 44 a9 28 b1 88 9a 40 b1 95 9a 1f 15 00 f1 01 01 00 54 08 00 40 b9 08 01 14 4a 09 10 40 39 4a 0a 80 52 29 01 0a 4a 08 01 09 2a e8 00 00 34 } //02 00 
		$a_00_2 = {74 34 0f 57 c0 48 8b 51 f8 49 89 57 f8 0f 10 49 e8 41 0f 11 4f e8 49 83 c7 e8 0f 11 41 e8 48 c7 41 f8 00 00 00 00 48 8d 51 e8 48 89 d1 48 39 c2 75 d3 4c 89 7d e0 48 8d 7d b8 } //03 00 
		$a_00_3 = {73 79 73 74 65 6d 5f 70 72 6f 66 69 6c 65 72 20 53 50 48 61 72 64 77 61 72 65 44 61 74 61 54 79 70 65 } //03 00  system_profiler SPHardwareDataType
		$a_00_4 = {73 79 73 74 65 6d 5f 70 72 6f 66 69 6c 65 72 20 73 70 64 69 73 70 6c 61 79 73 64 61 74 61 74 79 70 65 } //03 00  system_profiler spdisplaysdatatype
		$a_00_5 = {73 77 5f 76 65 72 73 } //00 00  sw_vers
	condition:
		any of ($a_*)
 
}