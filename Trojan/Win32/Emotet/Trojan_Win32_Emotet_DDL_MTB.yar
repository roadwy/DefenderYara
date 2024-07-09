
rule Trojan_Win32_Emotet_DDL_MTB{
	meta:
		description = "Trojan:Win32/Emotet.DDL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_00_0 = {8a c8 8a d3 0a d8 8b 44 24 24 f6 d2 f6 d1 0a d1 22 d3 88 14 07 } //1
		$a_02_1 = {03 c3 99 bb 7c 0d 00 00 f7 fb [0-1b] 03 c2 99 8b f3 f7 fe } //1
	condition:
		((#a_00_0  & 1)*1+(#a_02_1  & 1)*1) >=1
 
}