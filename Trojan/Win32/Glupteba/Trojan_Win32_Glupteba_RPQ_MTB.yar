
rule Trojan_Win32_Glupteba_RPQ_MTB{
	meta:
		description = "Trojan:Win32/Glupteba.RPQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_00_0 = {8d 0c 0a 8b 09 81 e1 ff 00 00 00 } //1
		$a_02_1 = {31 08 81 ee ?? ?? ?? ?? 89 fe 40 29 fe 4e 39 d8 75 dc } //1
	condition:
		((#a_00_0  & 1)*1+(#a_02_1  & 1)*1) >=1
 
}