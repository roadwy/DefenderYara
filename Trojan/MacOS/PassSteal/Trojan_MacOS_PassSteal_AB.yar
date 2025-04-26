
rule Trojan_MacOS_PassSteal_AB{
	meta:
		description = "Trojan:MacOS/PassSteal.AB,SIGNATURE_TYPE_MACHOHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_02_0 = {6f 73 61 73 63 72 69 70 74 20 2d 65 20 27 64 69 73 70 6c 61 79 20 64 69 61 6c 6f 67 [0-a0] 50 6c 65 61 73 65 20 65 6e 74 65 72 20 79 6f 75 72 20 70 61 73 73 77 6f 72 64 } //2
		$a_00_1 = {73 65 63 75 72 69 74 79 20 32 3e 26 31 20 3e 20 2f 64 65 76 2f 6e 75 6c 6c 20 66 69 6e 64 2d 67 65 6e 65 72 69 63 2d 70 61 73 73 77 6f 72 64 20 2d 67 61 20 27 43 68 72 6f 6d 65 27 20 7c 20 61 77 6b 20 27 7b 70 72 69 6e 74 20 24 32 7d 27 } //1 security 2>&1 > /dev/null find-generic-password -ga 'Chrome' | awk '{print $2}'
		$a_02_2 = {2f 4c 69 62 72 61 72 79 2f 41 70 70 6c 69 63 61 74 69 6f 6e 20 53 75 70 70 6f 72 74 2f 46 69 72 65 66 6f 78 2f 50 72 6f 66 69 6c 65 73 2f [0-a0] 63 6f 6f 6b 69 65 73 2e 73 71 6c 69 74 65 } //1
		$a_00_3 = {64 73 63 6c 20 2f 4c 6f 63 61 6c 2f 44 65 66 61 75 6c 74 20 2d 61 75 74 68 6f 6e 6c 79 } //1 dscl /Local/Default -authonly
	condition:
		((#a_02_0  & 1)*2+(#a_00_1  & 1)*1+(#a_02_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}