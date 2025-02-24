
rule Trojan_Win64_Zusy_HNAP_MTB{
	meta:
		description = "Trojan:Win64/Zusy.HNAP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 06 00 00 "
		
	strings :
		$a_01_0 = {76 53 52 78 45 48 74 47 54 65 56 51 4c 4c 52 6f 45 56 70 6a 57 64 72 57 54 45 4d 53 64 7a 70 56 69 6e 6d 51 46 4b 59 64 77 48 46 66 69 64 4a 69 54 52 69 41 61 7a 67 72 52 45 70 7a 6a 43 4c 62 67 6b 51 57 50 71 6f 62 67 59 4a 6b 49 46 63 66 4b 45 59 46 50 67 6e 4d 79 56 47 45 64 63 63 51 4f 75 4a 48 52 79 59 51 61 76 6a 70 73 6c 69 72 57 74 4c 69 58 46 54 79 7a 6c 55 74 41 4b 6d 4f 4d 45 4d 58 52 62 47 4f } //7 vSRxEHtGTeVQLLRoEVpjWdrWTEMSdzpVinmQFKYdwHFfidJiTRiAazgrREpzjCLbgkQWPqobgYJkIFcfKEYFPgnMyVGEdccQOuJHRyYQavjpslirWtLiXFTyzlUtAKmOMEMXRbGO
		$a_01_1 = {6d 6b 68 56 69 75 6c 50 69 71 48 48 4f 45 6f 63 43 76 56 63 69 4c 71 52 54 77 6b 67 77 47 48 63 67 52 54 42 6c 50 4b 6b 6b 41 78 46 56 4c 71 4d 48 7a 46 6c 66 43 41 41 62 67 53 61 63 67 78 65 42 4c 62 4d 79 61 70 78 51 77 4d 54 75 75 72 64 6e 46 62 58 43 6b 58 78 61 49 6d 69 } //7 mkhViulPiqHHOEocCvVciLqRTwkgwGHcgRTBlPKkkAxFVLqMHzFlfCAAbgSacgxeBLbMyapxQwMTuurdnFbXCkXxaImi
		$a_01_2 = {5a 65 62 61 5d 4a 47 55 68 7b 44 4a 6a 65 68 46 65 58 } //2 Zeba]JGUh{DJjehFeX
		$a_01_3 = {5a 6e 28 58 5c 63 6b 2b 4f 7c 6a 76 54 47 7d 21 6d 63 55 40 61 5e } //2 Zn(X\ck+O|jvTG}!mcU@a^
		$a_01_4 = {57 74 64 7b 54 7d 68 49 74 79 44 67 6e 45 62 63 58 43 } //2 Wtd{T}hItyDgnEbcXC
		$a_01_5 = {64 41 49 74 74 76 49 79 62 41 78 67 41 67 4e 66 } //2 dAIttvIybAxgAgNf
	condition:
		((#a_01_0  & 1)*7+(#a_01_1  & 1)*7+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2+(#a_01_4  & 1)*2+(#a_01_5  & 1)*2) >=11
 
}