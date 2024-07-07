
rule Trojan_Win32_Remcos_DDL_MTB{
	meta:
		description = "Trojan:Win32/Remcos.DDL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {31 00 02 04 d8 09 b0 04 bf 04 ef 01 0b 08 00 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}