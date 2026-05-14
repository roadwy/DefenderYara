
rule Trojan_Win32_DllHijack_LRC_MTB{
	meta:
		description = "Trojan:Win32/DllHijack.LRC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1e 00 1e 00 05 00 00 "
		
	strings :
		$a_03_0 = {8a 04 38 8b cf 88 45 cf b8 ?? ?? ?? ?? f7 e7 2b ca d1 e9 03 ca 8b d7 c1 e9 02 } //20
		$a_81_1 = {2d 2d 2d 20 64 65 63 72 79 70 74 20 5b 25 73 5d 20 2d 2d 2d } //1 --- decrypt [%s] ---
		$a_81_2 = {5b 25 73 5d 20 64 65 63 72 79 70 74 69 6e 67 2e 2e 2e } //2 [%s] decrypting...
		$a_81_3 = {5b 25 73 5d 20 64 65 63 72 79 70 74 20 4f 4b } //3 [%s] decrypt OK
		$a_81_4 = {5b 25 73 5d 20 53 48 41 2d 32 35 36 20 4f 4b } //4 [%s] SHA-256 OK
	condition:
		((#a_03_0  & 1)*20+(#a_81_1  & 1)*1+(#a_81_2  & 1)*2+(#a_81_3  & 1)*3+(#a_81_4  & 1)*4) >=30
 
}