
rule Trojan_Win32_Daonol_I{
	meta:
		description = "Trojan:Win32/Daonol.I,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {40 80 38 5a 74 03 83 c2 f8 48 ff d2 90 02 10 e8 90 01 04 e8 90 01 04 e8 90 01 04 e8 90 01 04 e8 90 01 04 e8 90 01 04 e8 90 01 04 e8 90 01 04 e8 90 01 04 e8 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}