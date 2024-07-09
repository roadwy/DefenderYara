
rule Trojan_Win32_Chepdu_X{
	meta:
		description = "Trojan:Win32/Chepdu.X,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {35 82 00 00 76 90 14 4e 83 fe 00 77 ?? 5e } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}