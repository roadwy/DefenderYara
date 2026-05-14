
rule Trojan_Win32_ValleyRat_ARP_AMTB{
	meta:
		description = "Trojan:Win32/ValleyRat.ARP!AMTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_80_0 = {68 74 74 70 3a 2f 2f 34 35 2e 32 30 33 2e 32 32 30 2e 31 33 35 3a 38 30 38 30 2f 6f 75 74 70 75 74 5f 38 36 2e 62 69 6e } //http://45.203.220.135:8080/output_86.bin  1
		$a_80_1 = {5b 2b 5d 20 44 6f 77 6e 6c 6f 61 64 65 64 20 61 6e 64 20 65 6e 63 72 79 70 74 65 64 20 25 64 20 62 79 74 65 73 } //[+] Downloaded and encrypted %d bytes  1
		$a_80_2 = {5b 2a 5d 20 53 74 61 72 74 69 6e 67 20 65 6e 63 72 79 70 74 65 64 20 64 6f 77 6e 6c 6f 61 64 20 6c 6f 61 64 65 72 } //[*] Starting encrypted download loader  1
		$a_80_3 = {72 75 6e 61 73 } //runas  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1) >=4
 
}