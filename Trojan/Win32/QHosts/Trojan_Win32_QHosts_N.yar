
rule Trojan_Win32_QHosts_N{
	meta:
		description = "Trojan:Win32/QHosts.N,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {40 65 63 68 6f 20 6f 66 66 0d 0a 40 65 63 68 6f 20 [0-04] 2e [0-04] 2e [0-04] 2e [0-05] 77 77 77 2e 62 61 6e 6b 6f 66 61 6d 65 72 69 63 61 2e 63 6f 6d 20 20 3e 3e 25 77 69 6e 64 69 72 25 5c 53 79 73 74 65 6d 33 32 5c 64 72 69 76 65 72 73 5c 65 74 63 5c 68 6f 73 74 73 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}