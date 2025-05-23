
rule Trojan_MacOS_AtomicSteal_D{
	meta:
		description = "Trojan:MacOS/AtomicSteal.D,SIGNATURE_TYPE_MACHOHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_00_0 = {43 68 72 6f 6d 69 75 6d 2f 00 2f 43 6f 6f 6b 69 65 73 00 4c 6f 67 69 6e 20 44 61 74 61 00 2f 50 61 73 73 77 6f 72 64 00 57 65 62 20 44 61 74 61 00 2f 41 75 74 6f 66 69 6c 6c } //1
		$a_00_1 = {2f 57 61 6c 6c 65 74 73 2f 00 5f 00 45 78 6f 64 75 73 00 45 6c 65 63 74 72 75 6d 00 43 6f 69 6e 6f 6d 69 00 47 75 61 72 64 61 00 57 61 73 61 62 69 } //1
		$a_00_2 = {73 79 73 74 65 6d 5f 70 72 6f 66 69 6c 65 72 20 53 50 44 69 73 70 6c 61 79 73 44 61 74 61 54 79 70 65 00 73 77 5f 76 65 72 73 } //1
		$a_00_3 = {64 73 63 6c 20 2f 4c 6f 63 61 6c 2f 44 65 66 61 75 6c 74 20 2d 61 75 74 68 6f 6e 6c 79 } //1 dscl /Local/Default -authonly
		$a_00_4 = {2f 4c 69 62 72 61 72 79 2f 4b 65 79 63 68 61 69 6e 73 2f 6c 6f 67 69 6e 2e 6b 65 79 63 68 61 69 6e 2d 64 62 } //1 /Library/Keychains/login.keychain-db
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=5
 
}