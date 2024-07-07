
rule Trojan_Win32_VBKrypt_BR_MTB{
	meta:
		description = "Trojan:Win32/VBKrypt.BR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_81_0 = {5c 53 70 72 65 61 64 53 68 65 65 74 68 2e 76 62 70 } //1 \SpreadSheeth.vbp
		$a_81_1 = {65 6e 65 6d 79 } //1 enemy
		$a_81_2 = {50 69 63 47 42 75 6c 6c 65 74 } //1 PicGBullet
		$a_81_3 = {43 6f 6c 6c 69 73 69 6f 6e 20 44 65 74 65 63 74 69 6f 6e } //1 Collision Detection
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=4
 
}