
rule Trojan_Win32_Bayrob_ARA_MTB{
	meta:
		description = "Trojan:Win32/Bayrob.ARA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {8a 10 30 11 41 40 3b cf 75 f6 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}
rule Trojan_Win32_Bayrob_ARA_MTB_2{
	meta:
		description = "Trojan:Win32/Bayrob.ARA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {80 39 00 74 ?? 80 31 1a 41 eb f5 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}