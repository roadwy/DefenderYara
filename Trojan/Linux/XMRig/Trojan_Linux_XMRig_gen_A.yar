
rule Trojan_Linux_XMRig_gen_A{
	meta:
		description = "Trojan:Linux/XMRig.gen!A!!XMRig.gen!A,SIGNATURE_TYPE_ARHSTR_EXT,03 00 03 00 07 00 00 "
		
	strings :
		$a_81_0 = {55 52 4c 20 6f 66 20 6d 69 6e 69 6e 67 20 73 65 72 76 65 72 } //1 URL of mining server
		$a_81_1 = {70 61 73 73 77 6f 72 64 20 66 6f 72 20 6d 69 6e 69 6e 67 20 73 65 72 76 65 72 } //1 password for mining server
		$a_81_2 = {2d 2d 63 70 75 2d 6d 61 78 2d 74 68 72 65 61 64 73 2d 68 69 6e 74 3d 4e } //1 --cpu-max-threads-hint=N
		$a_81_3 = {2d 2d 64 6f 6e 61 74 65 2d 6c 65 76 65 6c 3d 4e } //1 --donate-level=N
		$a_81_4 = {22 6e 69 63 65 68 61 73 68 22 3a 20 66 61 6c 73 65 } //1 "nicehash": false
		$a_81_5 = {22 61 6c 67 6f 22 3a 20 22 63 72 79 70 74 6f 6e 69 67 68 74 22 } //1 "algo": "cryptonight"
		$a_81_6 = {27 68 27 20 68 61 73 68 72 61 74 65 2c 20 27 70 27 20 70 61 75 73 65 2c 20 27 72 27 20 72 65 73 75 6d 65 } //1 'h' hashrate, 'p' pause, 'r' resume
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1) >=3
 
}