
rule Trojan_Win32_Nitol_A_MTB{
	meta:
		description = "Trojan:Win32/Nitol.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {8a 04 3a 34 90 01 01 04 90 01 01 88 04 3a 42 3b d1 90 00 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}