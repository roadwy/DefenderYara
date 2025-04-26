
rule Ransom_Win32_Revil_SH_MTB{
	meta:
		description = "Ransom:Win32/Revil.SH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_81_0 = {22 66 6c 73 22 3a 5b 22 62 6f 6f 74 2e 69 6e 69 22 2c 22 69 63 6f 6e 63 61 63 68 65 2e 64 62 22 2c 22 62 6f 6f 74 73 65 63 74 2e 62 61 6b 22 2c 22 74 68 75 6d 62 73 2e 64 62 22 } //1 "fls":["boot.ini","iconcache.db","bootsect.bak","thumbs.db"
		$a_81_1 = {22 64 6d 6e 22 3a 22 72 61 76 65 6e 73 6e 65 73 74 68 6f 6d 65 67 6f 6f 64 73 2e 63 6f 6d 3b 68 79 70 6f 7a 65 6e 74 72 75 6d 2e 63 6f 6d 3b 78 6e 2d 2d 73 69 6e 67 6c 65 62 72 73 65 6e 2d 76 65 72 67 6c 65 69 63 68 2d 6e 65 63 2e 63 6f 6d 3b } //1 "dmn":"ravensnesthomegoods.com;hypozentrum.com;xn--singlebrsen-vergleich-nec.com;
		$a_81_2 = {22 70 72 63 22 3a 5b 22 6d 73 61 63 63 65 73 73 22 2c 22 69 6e 66 6f 70 61 74 68 22 2c 22 6f 72 61 63 6c 65 22 2c 22 65 6e 63 73 76 63 22 } //1 "prc":["msaccess","infopath","oracle","encsvc"
		$a_81_3 = {22 65 78 74 22 3a 5b 22 63 70 6c 22 2c 22 6f 63 78 22 2c 22 6d 73 70 22 2c 22 33 38 36 22 2c 22 63 61 62 22 2c 22 63 75 72 22 2c 22 6d 6f 64 22 } //1 "ext":["cpl","ocx","msp","386","cab","cur","mod"
		$a_81_4 = {22 6e 6e 61 6d 65 22 3a 22 7b 45 58 54 7d 2d } //1 "nname":"{EXT}-
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1) >=5
 
}