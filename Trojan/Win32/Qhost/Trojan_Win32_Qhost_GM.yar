
rule Trojan_Win32_Qhost_GM{
	meta:
		description = "Trojan:Win32/Qhost.GM,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_11_0 = {63 68 6f 20 31 38 34 2e 38 32 2e 31 34 36 2e 38 36 20 68 74 74 70 3a 2f 2f 68 6f 74 6d 61 69 6c 2e 63 6f 6d 20 3e 3e 20 25 77 69 6e 64 69 72 25 5c 73 79 73 74 65 6d 33 32 5c 64 72 69 76 65 72 73 5c 65 74 63 5c 68 6f 73 74 73 01 } //1
		$a_65_1 = {68 6f 20 31 38 34 2e 38 32 2e 31 34 36 2e 38 36 20 } //20224 ho 184.82.146.86 
	condition:
		((#a_11_0  & 1)*1+(#a_65_1  & 1)*20224) >=2
 
}