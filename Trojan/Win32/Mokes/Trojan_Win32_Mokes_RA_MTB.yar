
rule Trojan_Win32_Mokes_RA_MTB{
	meta:
		description = "Trojan:Win32/Mokes.RA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {e2 14 42 fc cf 79 86 c8 e8 00 00 00 00 75 04 74 02 bc 55 8b 1c 24 83 c4 04 eb 0a 40 81 eb 49 32 00 00 eb 05 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}