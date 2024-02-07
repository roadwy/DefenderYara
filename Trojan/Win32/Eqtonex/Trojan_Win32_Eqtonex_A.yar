
rule Trojan_Win32_Eqtonex_A{
	meta:
		description = "Trojan:Win32/Eqtonex.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_00_0 = {69 c9 6d a9 33 60 ba 8f 3b 48 dd 2b d1 8b ca c1 ea 08 30 10 40 } //01 00 
		$a_01_1 = {70 00 72 00 6b 00 4d 00 74 00 78 00 } //00 00  prkMtx
		$a_00_2 = {5d } //04 00  ]
	condition:
		any of ($a_*)
 
}