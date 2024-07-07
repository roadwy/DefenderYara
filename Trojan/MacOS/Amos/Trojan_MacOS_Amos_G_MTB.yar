
rule Trojan_MacOS_Amos_G_MTB{
	meta:
		description = "Trojan:MacOS/Amos.G!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {2f 2e 77 61 6c 6c 65 74 77 61 73 61 62 69 2f 63 6c 69 65 6e 74 2f 57 61 6c 6c 65 74 73 2f } //1 /.walletwasabi/client/Wallets/
		$a_00_1 = {41 4d 4f 53 20 73 74 65 61 6c 73 20 79 6f 75 72 20 70 61 73 73 77 6f 72 64 73 } //1 AMOS steals your passwords
		$a_00_2 = {73 65 63 75 72 69 74 79 20 32 3e 26 31 20 3e 20 2f 64 65 76 2f 6e 75 6c 6c 20 66 69 6e 64 2d 67 65 6e 65 72 69 63 2d 70 61 73 73 77 6f 72 64 20 2d 67 61 20 27 43 68 72 6f 6d 65 27 } //1 security 2>&1 > /dev/null find-generic-password -ga 'Chrome'
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}