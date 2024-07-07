
rule Trojan_Win32_Qukart_RPP_MTB{
	meta:
		description = "Trojan:Win32/Qukart.RPP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {31 08 90 90 90 90 90 83 c0 04 90 90 90 90 90 39 d8 90 90 90 90 75 e9 } //1
		$a_01_1 = {90 89 c8 90 90 90 f7 f7 90 91 90 90 90 90 90 90 90 90 58 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}