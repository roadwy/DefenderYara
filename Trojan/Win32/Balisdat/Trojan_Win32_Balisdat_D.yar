
rule Trojan_Win32_Balisdat_D{
	meta:
		description = "Trojan:Win32/Balisdat.D,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {66 7a 66 2e 65 71 76 6f 6a 61 5c 74 73 66 78 6a 73 65 5c 3a 44 } //1 fzf.eqvoja\tsfxjse\:D
		$a_01_1 = {66 7a 66 2e 6f 74 6e 5c 74 73 66 78 6a 73 65 5c 3a 44 } //1 fzf.otn\tsfxjse\:D
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}