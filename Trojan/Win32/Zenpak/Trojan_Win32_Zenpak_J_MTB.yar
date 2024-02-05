
rule Trojan_Win32_Zenpak_J_MTB{
	meta:
		description = "Trojan:Win32/Zenpak.J!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_01_0 = {8a 14 1e 47 8a 0c 07 8b c6 32 d1 88 14 1e 99 f7 } //00 00 
	condition:
		any of ($a_*)
 
}