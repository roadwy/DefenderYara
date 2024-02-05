
rule Trojan_Win32_Cordimik_RPA_MTB{
	meta:
		description = "Trojan:Win32/Cordimik.RPA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {5b 87 fa 88 10 c1 ea 1c f9 72 01 19 2b d7 f3 1b d6 e8 02 00 00 00 d2 e9 5a f3 1b d7 } //00 00 
	condition:
		any of ($a_*)
 
}