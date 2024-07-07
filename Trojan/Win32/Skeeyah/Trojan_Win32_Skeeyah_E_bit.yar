
rule Trojan_Win32_Skeeyah_E_bit{
	meta:
		description = "Trojan:Win32/Skeeyah.E!bit,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 7c 24 2c 31 fb 33 5c 24 04 8b 7c 24 10 31 fb 89 d8 88 44 24 08 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}