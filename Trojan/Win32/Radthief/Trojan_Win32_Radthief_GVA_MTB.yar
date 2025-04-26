
rule Trojan_Win32_Radthief_GVA_MTB{
	meta:
		description = "Trojan:Win32/Radthief.GVA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 45 cc 30 04 37 46 8b 45 d8 8b 7d d4 83 45 c4 11 89 45 bc 2b c7 89 75 b4 3b f0 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}