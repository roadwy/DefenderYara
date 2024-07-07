
rule Trojan_Win32_Fursto_E{
	meta:
		description = "Trojan:Win32/Fursto.E,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {50 55 ff d7 85 c0 74 57 68 90 01 02 00 10 55 56 ff d7 85 c0 74 4a 8b 3d 90 01 02 00 10 6a 00 56 ff 15 90 01 02 00 10 85 c0 74 33 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}