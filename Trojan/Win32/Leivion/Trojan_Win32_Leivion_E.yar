
rule Trojan_Win32_Leivion_E{
	meta:
		description = "Trojan:Win32/Leivion.E,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {28 0b 00 00 0a 11 05 16 20 bf 00 00 00 9c 11 05 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}