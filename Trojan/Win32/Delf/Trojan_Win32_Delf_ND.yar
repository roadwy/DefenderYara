
rule Trojan_Win32_Delf_ND{
	meta:
		description = "Trojan:Win32/Delf.ND,SIGNATURE_TYPE_PEHSTR,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {64 6e 66 33 36 30 2e 63 6f 6d } //01 00  dnf360.com
		$a_01_1 = {64 6e 66 77 67 2e 63 6f 6d } //01 00  dnfwg.com
		$a_01_2 = {77 67 78 7a 2e 6e 65 74 } //01 00  wgxz.net
		$a_01_3 = {54 68 75 6e 64 65 72 2e 44 4c 4c } //00 00  Thunder.DLL
	condition:
		any of ($a_*)
 
}