
rule Trojan_Win32_PonyStealer_B_MTB{
	meta:
		description = "Trojan:Win32/PonyStealer.B!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_03_0 = {ff 34 0f 81 [0-20] 58 [0-20] e8 [0-20] 89 04 0f [0-20] 83 e9 fc [0-20] 75 [0-20] 57 [0-20] c3 } //1
		$a_03_1 = {ff 34 0f 66 [0-20] 58 [0-20] e8 [0-20] 89 04 0f [0-20] 83 e9 fc [0-20] 75 [0-20] 57 [0-20] c3 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=1
 
}