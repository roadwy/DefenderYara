
rule Trojan_WinNT_Alureon_S{
	meta:
		description = "Trojan:WinNT/Alureon.S,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {8b 47 24 23 c3 0d 20 00 00 a8 89 47 24 8b 7d 0c 83 66 58 00 } //1
		$a_01_1 = {5b 69 6e 6a 65 63 74 73 5f 65 6e 64 5d } //1 [injects_end]
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}