
rule Trojan_MacOS_AtomicSteal_B{
	meta:
		description = "Trojan:MacOS/AtomicSteal.B,SIGNATURE_TYPE_MACHOHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {6f 70 65 6e 73 73 6c 20 65 6e 63 20 2d 62 61 73 65 36 34 20 2d 64 20 2d 61 65 73 2d 31 32 38 2d 63 62 63 20 2d 69 76 20 27 32 30 32 30 32 30 32 30 32 30 32 30 32 30 32 30 32 30 32 30 32 30 32 30 32 30 32 30 32 30 32 30 27 } //1 openssl enc -base64 -d -aes-128-cbc -iv '20202020202020202020202020202020'
		$a_00_1 = {73 65 63 75 72 69 74 79 20 32 3e 26 31 20 3e 20 2f 64 65 76 2f 6e 75 6c 6c 20 66 69 6e 64 2d 67 65 6e 65 72 69 63 2d 70 61 73 73 77 6f 72 64 20 2d 67 61 20 27 43 68 72 6f 6d 65 27 } //1 security 2>&1 > /dev/null find-generic-password -ga 'Chrome'
		$a_00_2 = {41 54 4f 4d 49 43 20 53 54 45 41 4c 45 52 20 43 4f 4f 43 4b 49 45 2e 50 52 4f } //1 ATOMIC STEALER COOCKIE.PRO
		$a_00_3 = {57 61 6c 6c 65 74 73 2f 42 69 74 63 6f 69 6e } //1 Wallets/Bitcoin
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}