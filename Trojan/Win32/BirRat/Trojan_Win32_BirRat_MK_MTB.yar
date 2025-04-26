
rule Trojan_Win32_BirRat_MK_MTB{
	meta:
		description = "Trojan:Win32/BirRat.MK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 10 00 00 "
		
	strings :
		$a_81_0 = {2d 2d 2d 2d 2d 42 45 47 49 4e 20 50 55 42 4c 49 43 20 4b 45 59 2d 2d 2d 2d 2d } //1 -----BEGIN PUBLIC KEY-----
		$a_81_1 = {2d 2d 2d 2d 2d 45 4e 44 20 50 55 42 4c 49 43 20 4b 45 59 2d 2d 2d 2d 2d } //1 -----END PUBLIC KEY-----
		$a_81_2 = {45 73 74 61 62 6c 69 73 68 20 48 54 54 50 20 70 72 6f 78 79 20 74 75 6e 6e 65 6c 20 74 6f 20 25 73 3a 25 68 } //1 Establish HTTP proxy tunnel to %s:%h
		$a_81_3 = {4b 65 72 62 65 72 6f 73 } //1 Kerberos
		$a_81_4 = {64 65 63 72 79 70 74 20 70 61 73 73 77 6f 72 64 } //1 decrypt password
		$a_81_5 = {43 6f 6d 70 72 6f 6d 69 73 65 } //1 Compromise
		$a_81_6 = {73 65 73 73 69 6f 6e 5f 69 64 } //1 session_id
		$a_81_7 = {6d 61 73 74 65 72 5f 6b 65 79 } //1 master_key
		$a_81_8 = {6b 65 79 5f 61 72 67 } //1 key_arg
		$a_81_9 = {42 6f 74 20 49 44 3a } //1 Bot ID:
		$a_81_10 = {55 73 65 72 3a } //1 User:
		$a_81_11 = {53 6f 66 74 77 61 72 65 5c 53 79 73 69 6e 74 65 72 6e 61 6c 73 5c 41 75 74 6f 52 75 6e 73 } //1 Software\Sysinternals\AutoRuns
		$a_81_12 = {52 4f 4f 54 5c 43 49 4d 56 32 } //1 ROOT\CIMV2
		$a_81_13 = {78 6d 72 6d 69 6e 65 } //1 xmrmine
		$a_81_14 = {78 6d 72 36 34 5f 6d 69 6e 65 5f 73 74 61 72 74 } //1 xmr64_mine_start
		$a_81_15 = {43 6c 69 70 62 6f 61 72 64 3a } //1 Clipboard:
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1+(#a_81_8  & 1)*1+(#a_81_9  & 1)*1+(#a_81_10  & 1)*1+(#a_81_11  & 1)*1+(#a_81_12  & 1)*1+(#a_81_13  & 1)*1+(#a_81_14  & 1)*1+(#a_81_15  & 1)*1) >=13
 
}