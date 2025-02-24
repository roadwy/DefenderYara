
rule Trojan_Linux_LockBitRansom_B{
	meta:
		description = "Trojan:Linux/LockBitRansom.B,SIGNATURE_TYPE_CMDHSTR_EXT,15 00 15 00 05 00 00 "
		
	strings :
		$a_00_0 = {73 00 69 00 6d 00 75 00 6c 00 61 00 74 00 65 00 } //10 simulate
		$a_00_1 = {2d 00 65 00 78 00 74 00 65 00 6e 00 73 00 69 00 6f 00 6e 00 73 00 20 00 6c 00 6f 00 63 00 6b 00 62 00 69 00 74 00 } //1 -extensions lockbit
		$a_00_2 = {2d 00 65 00 78 00 74 00 65 00 6e 00 73 00 69 00 6f 00 6e 00 73 00 20 00 72 00 79 00 75 00 6b 00 } //1 -extensions ryuk
		$a_00_3 = {2d 00 65 00 78 00 74 00 65 00 6e 00 73 00 69 00 6f 00 6e 00 73 00 20 00 65 00 6e 00 63 00 } //1 -extensions enc
		$a_00_4 = {2d 00 70 00 75 00 62 00 6c 00 69 00 63 00 6b 00 65 00 79 00 } //10 -publickey
	condition:
		((#a_00_0  & 1)*10+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*10) >=21
 
}