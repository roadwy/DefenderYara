
rule Trojan_Win32_Miuref_E{
	meta:
		description = "Trojan:Win32/Miuref.E,SIGNATURE_TYPE_PEHSTR_EXT,ffffffc8 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {89 3c 24 81 2c 24 78 54 cb 32 58 50 89 1c 24 bb 78 54 cb 32 01 d8 5b 00 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}