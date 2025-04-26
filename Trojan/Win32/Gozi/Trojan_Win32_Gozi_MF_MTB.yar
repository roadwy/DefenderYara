
rule Trojan_Win32_Gozi_MF_MTB{
	meta:
		description = "Trojan:Win32/Gozi.MF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 00 8b 12 33 03 89 34 24 89 54 24 04 89 44 24 08 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}