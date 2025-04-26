
rule Trojan_MacOS_Amos_E_MTB{
	meta:
		description = "Trojan:MacOS/Amos.E!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {6c 6f 67 69 6e 75 73 65 72 73 2e 76 64 66 00 63 6f 6e 66 69 67 2e 76 64 66 00 53 74 65 61 6d 2f 6c 6f 67 69 6e 75 73 65 72 73 2e 76 64 66 00 53 74 65 61 6d 2f 63 6f 6e 66 69 67 2e 76 64 66 } //1
		$a_00_1 = {73 65 63 75 72 69 74 79 20 32 3e 26 31 20 3e 20 2f 64 65 76 2f 6e 75 6c 6c 20 66 69 6e 64 2d 67 65 6e 65 72 69 63 2d 70 61 73 73 77 6f 72 64 20 2d 67 61 20 27 43 68 72 6f 6d 65 27 } //1 security 2>&1 > /dev/null find-generic-password -ga 'Chrome'
		$a_00_2 = {64 65 73 6b 77 61 6c 6c 65 74 73 2f 61 74 6f 6d 69 63 2f } //1 deskwallets/atomic/
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}