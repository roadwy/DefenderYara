
rule Trojan_Win32_SystemBC_KAA_MTB{
	meta:
		description = "Trojan:Win32/SystemBC.KAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b c6 8d 0c 2e f7 74 24 ?? 2b d3 8a 44 14 ?? 32 04 0f 46 88 01 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}