
rule Trojan_MacOS_AtomicSteal_A{
	meta:
		description = "Trojan:MacOS/AtomicSteal.A,SIGNATURE_TYPE_MACHOHSTR_EXT,04 00 04 00 05 00 00 "
		
	strings :
		$a_00_0 = {73 65 63 75 72 69 74 79 20 32 3e 26 31 20 3e 20 2f 64 65 76 2f 6e 75 6c 6c 20 66 69 6e 64 2d 67 65 6e 65 72 69 63 2d 70 61 73 73 77 6f 72 64 20 2d 67 61 20 27 43 68 72 6f 6d 65 27 } //1 security 2>&1 > /dev/null find-generic-password -ga 'Chrome'
		$a_00_1 = {52 6f 6e 69 6e 20 57 61 6c 6c 65 74 53 45 52 49 41 4c 4e 55 4d 42 45 52 53 65 63 50 6f 6c 69 63 79 4f 69 64 53 6f 72 61 5f 53 6f 6d 70 65 6e 67 53 79 6c 6f 74 69 5f 4e 61 67 72 69 54 72 75 73 74 20 57 61 6c 6c 65 74 } //1 Ronin WalletSERIALNUMBERSecPolicyOidSora_SompengSyloti_NagriTrust Wallet
		$a_03_2 = {68 74 74 70 3a 2f 2f [0-10] 69 57 61 6c 6c 65 74 69 6e 76 61 6c 69 64 6c 6f 6f 6b 75 70 20 6d 69 6e 70 63 3d 20 6e 69 6c } //1
		$a_00_3 = {2f 55 73 65 72 73 2f 69 6c 75 68 61 62 6f 6c 74 6f 76 2f 44 65 73 6b 74 6f 70 2f 61 6d 6f 73 } //1 /Users/iluhaboltov/Desktop/amos
		$a_00_4 = {68 74 74 70 3a 2f 2f 61 6d 6f 73 2d 6d 61 6c 77 61 72 65 2e 72 75 2f 73 65 6e 64 6c 6f 67 } //1 http://amos-malware.ru/sendlog
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_03_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=4
 
}