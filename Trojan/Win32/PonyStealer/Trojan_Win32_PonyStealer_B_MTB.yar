
rule Trojan_Win32_PonyStealer_B_MTB{
	meta:
		description = "Trojan:Win32/PonyStealer.B!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_03_0 = {ff 34 0f 81 90 02 20 58 90 02 20 e8 90 02 20 89 04 0f 90 02 20 83 e9 fc 90 02 20 75 90 02 20 57 90 02 20 c3 90 00 } //1
		$a_03_1 = {ff 34 0f 66 90 02 20 58 90 02 20 e8 90 02 20 89 04 0f 90 02 20 83 e9 fc 90 02 20 75 90 02 20 57 90 02 20 c3 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=1
 
}