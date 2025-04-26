
rule Trojan_Linux_DokSpy_A{
	meta:
		description = "Trojan:Linux/DokSpy.A,SIGNATURE_TYPE_MACHOHSTR_EXT,06 00 06 00 07 00 00 "
		
	strings :
		$a_00_0 = {6b 69 6c 6c 61 6c 6c 20 53 61 66 61 72 69 } //1 killall Safari
		$a_00_1 = {73 75 64 6f 20 2d 75 20 25 40 20 25 40 20 69 6e 73 74 61 6c 6c 20 74 6f 72 } //1 sudo -u %@ %@ install tor
		$a_00_2 = {73 75 64 6f 20 2d 75 20 25 40 20 25 40 20 73 65 72 76 69 63 65 73 20 73 74 61 72 74 20 74 6f 72 } //1 sudo -u %@ %@ services start tor
		$a_00_3 = {74 63 70 34 2d 4c 49 53 54 45 4e 3a 35 35 35 35 2c 72 65 75 73 65 61 64 64 72 2c 66 6f 72 6b 2c 6b 65 65 70 61 6c 69 76 65 2c 62 69 6e 64 3d 31 32 37 2e 30 2e 30 2e 31 } //1 tcp4-LISTEN:5555,reuseaddr,fork,keepalive,bind=127.0.0.1
		$a_00_4 = {73 65 63 75 72 69 74 79 20 61 64 64 2d 74 72 75 73 74 65 64 2d 63 65 72 74 20 2d 64 20 2d 72 20 74 72 75 73 74 52 6f 6f 74 20 2d 6b 20 2f 4c 69 62 72 61 72 79 2f 4b 65 79 63 68 61 69 6e 73 2f 53 } //1 security add-trusted-cert -d -r trustRoot -k /Library/Keychains/S
		$a_00_5 = {70 61 6f 79 75 37 67 75 62 37 32 6c 79 6b 75 6b 2e 6f 6e 69 6f 6e } //1 paoyu7gub72lykuk.onion
		$a_00_6 = {63 68 6d 6f 64 20 2b 78 20 25 40 20 26 26 20 72 6d 20 2d 66 20 25 40 } //1 chmod +x %@ && rm -f %@
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1) >=6
 
}