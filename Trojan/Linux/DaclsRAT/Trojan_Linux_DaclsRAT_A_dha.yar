
rule Trojan_Linux_DaclsRAT_A_dha{
	meta:
		description = "Trojan:Linux/DaclsRAT.A!dha,SIGNATURE_TYPE_MACHOHSTR_EXT,01 00 01 00 03 00 00 "
		
	strings :
		$a_00_0 = {30 31 2f 69 6d 61 67 65 73 2e 74 67 7a 2e 30 30 31 20 3e 20 2f 64 65 76 2f 6e 75 6c 6c 20 32 3e 26 31 20 26 26 20 63 68 6d 6f 64 20 2b 78 20 7e 2f 4c 69 62 72 61 72 79 2f 2e 6d 69 6e 61 20 3e 20 2f 64 65 76 2f 6e 75 6c 6c 20 32 3e 26 31 20 } //1 01/images.tgz.001 > /dev/null 2>&1 && chmod +x ~/Library/.mina > /dev/null 2>&1 
		$a_00_1 = {a0 d2 89 29 27 78 75 f6 aa 78 c7 98 39 a0 05 ed 39 18 82 62 33 ea 18 bb 18 30 78 97 a9 e1 8a 92 } //1
		$a_00_2 = {63 68 65 63 6b 00 7b 22 72 65 73 75 6c 74 22 3a 22 6f 6b 22 7d 00 73 61 76 65 00 73 65 73 73 69 6f 6e 5f 69 64 00 76 61 6c 75 65 00 25 59 2d 25 6d 2d 25 64 20 25 58 00 53 43 41 4e 09 25 73 09 25 64 2e 25 64 2e 25 64 2e 25 64 09 25 64 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=1
 
}