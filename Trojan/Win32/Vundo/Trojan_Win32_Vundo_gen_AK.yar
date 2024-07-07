
rule Trojan_Win32_Vundo_gen_AK{
	meta:
		description = "Trojan:Win32/Vundo.gen!AK,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_13_0 = {03 00 00 00 90 01 03 5b eb 90 14 83 c3 90 01 01 eb 90 14 ff e3 90 00 00 } //1
	condition:
		((#a_13_0  & 1)*1) >=1
 
}