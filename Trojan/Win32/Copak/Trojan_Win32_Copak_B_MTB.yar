
rule Trojan_Win32_Copak_B_MTB{
	meta:
		description = "Trojan:Win32/Copak.B!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {74 01 ea 31 02 81 e9 90 01 04 81 c2 04 00 00 00 21 d9 41 39 fa 75 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}