
rule Trojan_Win32_Copak_H_MTB{
	meta:
		description = "Trojan:Win32/Copak.H!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_01_0 = {29 c9 09 c9 31 32 42 49 89 f9 39 c2 75 e8 01 ff 21 cf c3 } //00 00 
	condition:
		any of ($a_*)
 
}