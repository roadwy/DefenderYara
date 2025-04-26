
rule Trojan_Win64_SystemBC_E{
	meta:
		description = "Trojan:Win64/SystemBC.E,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {48 8b 44 24 78 48 8b 90 90 30 01 00 00 48 8b 44 24 78 48 8b ?? 20 01 00 00 48 8b 44 24 78 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}