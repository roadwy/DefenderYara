
rule Trojan_Win32_Hupigon_AA_MTB{
	meta:
		description = "Trojan:Win32/Hupigon.AA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {10 8b 84 24 90 01 01 01 00 00 73 07 8d 84 24 90 01 01 01 00 00 8a 90 01 01 38 8b 44 24 90 01 01 30 90 01 01 06 8b 90 01 01 24 90 01 01 83 c6 01 eb 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}