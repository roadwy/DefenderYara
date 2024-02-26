
rule Trojan_Win32_Ekstak_ASDR_MTB{
	meta:
		description = "Trojan:Win32/Ekstak.ASDR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 05 00 "
		
	strings :
		$a_01_0 = {2a 01 00 00 00 aa 13 3a 00 1c 77 36 00 00 c0 0a 00 0d 15 b6 76 4f f4 35 00 00 d4 00 00 b5 26 7f 6c } //05 00 
		$a_01_1 = {2a 01 00 00 00 1a 66 3a 00 8c c9 36 00 00 c0 0a 00 0d 15 b6 76 cf 46 36 00 00 d4 00 00 17 4b d1 ef } //00 00 
	condition:
		any of ($a_*)
 
}