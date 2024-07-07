
rule Trojan_Win32_Vatet_ZA_dha{
	meta:
		description = "Trojan:Win32/Vatet.ZA!dha,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {68 00 00 00 10 90 01 01 ff 15 90 01 04 8b 90 01 01 83 90 01 01 ff 90 02 06 6a 00 6a 00 6a 00 6a 04 6a 00 90 01 01 ff 15 90 07 08 01 0f 10 90 01 02 66 0f f8 90 01 01 66 0f ef 90 01 01 66 0f f8 90 01 01 0f 11 90 01 02 83 90 01 01 10 3b 90 01 01 72 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}