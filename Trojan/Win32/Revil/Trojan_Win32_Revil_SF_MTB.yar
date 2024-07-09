
rule Trojan_Win32_Revil_SF_MTB{
	meta:
		description = "Trojan:Win32/Revil.SF!MTB!!Revil.gen!MTB,SIGNATURE_TYPE_ARHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_81_0 = {44 6f 75 62 6c 65 20 72 75 6e 20 6e 6f 74 20 61 6c 6c 6f 77 65 64 21 } //1 Double run not allowed!
		$a_81_1 = {7b 45 58 54 7d 2d 72 65 61 64 6d 65 2e 74 78 74 } //1 {EXT}-readme.txt
		$a_81_2 = {22 66 6c 73 22 3a 5b 22 62 6f 6f 74 2e 69 6e 69 22 2c 22 69 63 6f 6e 63 61 63 68 65 2e 64 62 22 2c 22 62 6f 6f 74 73 65 63 74 2e 62 61 6b 22 2c } //1 "fls":["boot.ini","iconcache.db","bootsect.bak",
		$a_03_3 = {22 73 75 62 22 3a 22 [0-08] 22 2c 22 64 62 67 22 3a [0-08] 2c 22 65 74 22 3a [0-02] 2c 22 77 69 70 65 22 3a [0-05] 2c 22 77 68 74 22 3a 7b } //1
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_03_3  & 1)*1) >=4
 
}