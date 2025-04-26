
rule Trojan_Win32_GoelExaram_B{
	meta:
		description = "Trojan:Win32/GoelExaram.B,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {45 78 61 72 61 6d 65 6c 2d 57 69 6e 64 6f 77 73 2e 64 6c 6c 00 53 74 61 72 74 00 5f 63 67 6f 5f 64 75 6d 6d 79 5f 65 78 70 6f 72 74 } //3 硅牡浡汥圭湩潤獷搮汬匀慴瑲开杣彯畤浭役硥潰瑲
		$a_01_1 = {61 74 74 61 63 6b 65 76 61 6c 73 2e 6d 69 74 72 65 2d 65 6e 67 65 6e 75 69 74 79 2e 6f 72 67 2f 65 78 61 72 61 6d 65 6c 2d 77 69 6e 64 6f 77 73 2f 63 32 } //1 attackevals.mitre-engenuity.org/exaramel-windows/c2
		$a_01_2 = {61 74 74 61 63 6b 65 76 61 6c 73 2e 6d 69 74 72 65 2d 65 6e 67 65 6e 75 69 74 79 2e 6f 72 67 2f 65 78 61 72 61 6d 65 6c 2d 77 69 6e 64 6f 77 73 2f 64 69 73 63 6f 76 65 72 79 } //1 attackevals.mitre-engenuity.org/exaramel-windows/discovery
		$a_01_3 = {61 74 74 61 63 6b 65 76 61 6c 73 2e 6d 69 74 72 65 2d 65 6e 67 65 6e 75 69 74 79 2e 6f 72 67 2f 65 78 61 72 61 6d 65 6c 2d 77 69 6e 64 6f 77 73 2f 65 78 65 63 75 74 65 } //1 attackevals.mitre-engenuity.org/exaramel-windows/execute
		$a_01_4 = {61 74 74 61 63 6b 65 76 61 6c 73 2e 6d 69 74 72 65 2d 65 6e 67 65 6e 75 69 74 79 2e 6f 72 67 2f 65 78 61 72 61 6d 65 6c 2d 77 69 6e 64 6f 77 73 2f 66 69 6c 65 73 } //1 attackevals.mitre-engenuity.org/exaramel-windows/files
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}