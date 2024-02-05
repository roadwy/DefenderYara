
rule Trojan_Win32_Farfli_DFD_MTB{
	meta:
		description = "Trojan:Win32/Farfli.DFD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {8a 44 1e 01 8a 14 39 46 32 d0 8b c1 88 14 39 99 bd 05 00 00 00 f7 fd 85 d2 75 02 33 f6 8b 44 24 18 41 3b c8 7c da } //00 00 
	condition:
		any of ($a_*)
 
}