
rule Trojan_Win32_Copak_S_MTB{
	meta:
		description = "Trojan:Win32/Copak.S!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_02_0 = {d8 85 40 00 29 d2 e8 90 01 04 31 1e 81 ea 90 01 04 81 c2 90 01 04 81 c6 90 01 04 09 c0 81 e8 90 01 04 39 ce 75 d4 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}