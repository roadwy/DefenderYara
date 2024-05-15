
rule Trojan_Win32_Ekstak_SP_MTB{
	meta:
		description = "Trojan:Win32/Ekstak.SP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_01_0 = {33 c9 b2 80 84 94 0c 18 02 00 00 74 0f 66 8b 74 0c 10 66 3b b4 0c 20 04 00 00 75 1c 83 c0 02 83 c1 02 66 83 38 00 } //00 00 
	condition:
		any of ($a_*)
 
}