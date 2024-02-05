
rule Trojan_Win32_Dridex_RST_MTB{
	meta:
		description = "Trojan:Win32/Dridex.RST!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_81_0 = {69 6f 69 6e 6c 6f 69 65 38 52 52 69 65 54 64 54 69 65 54 72 65 76 54 6d 54 6e 65 73 } //01 00 
		$a_81_1 = {37 69 6e 72 6e 50 61 65 64 6f 72 61 61 73 4d 61 65 6c 6f 77 73 65 } //01 00 
		$a_81_2 = {72 65 65 4b 69 72 37 34 72 5a 44 76 72 72 72 69 72 6e } //00 00 
	condition:
		any of ($a_*)
 
}