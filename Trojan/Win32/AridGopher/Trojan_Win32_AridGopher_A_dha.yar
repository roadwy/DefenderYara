
rule Trojan_Win32_AridGopher_A_dha{
	meta:
		description = "Trojan:Win32/AridGopher.A!dha,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {44 49 52 3d 57 69 6e 64 6f 77 73 50 65 72 63 65 70 74 69 6f 6e 53 65 72 76 69 63 65 0d 0a 45 4e 44 50 4f 49 4e 54 3d 68 74 74 70 3a 2f 2f } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}