
rule Trojan_Win32_Pony_I_MTB{
	meta:
		description = "Trojan:Win32/Pony.I!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {c3 8b c0 53 51 8b d8 54 6a 40 52 53 90 09 07 00 8b c0 90 05 04 01 90 80 30 90 01 01 90 05 04 01 90 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}