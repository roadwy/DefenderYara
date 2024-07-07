
rule Trojan_WinNT_Cutwail_D_sys{
	meta:
		description = "Trojan:WinNT/Cutwail.D!sys,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {eb d4 5e 8b fe 8b 76 24 03 f3 66 8b 14 56 2b 57 10 42 8b 77 1c 03 f3 8b 04 96 03 c3 6a 00 68 2e 64 6c 6c 68 77 73 79 73 54 ff d0 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}