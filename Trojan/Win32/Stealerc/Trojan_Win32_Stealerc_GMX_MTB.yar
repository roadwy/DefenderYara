
rule Trojan_Win32_Stealerc_GMX_MTB{
	meta:
		description = "Trojan:Win32/Stealerc.GMX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {6a 00 6a 00 80 34 28 ?? ff d6 6a 00 ff d7 6a 00 ff d3 8b 44 24 ?? 6a 00 6a 00 80 34 28 ?? ff d6 6a 00 ff d7 6a 00 ff d3 8b 44 24 ?? 6a 00 6a 00 80 04 28 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}