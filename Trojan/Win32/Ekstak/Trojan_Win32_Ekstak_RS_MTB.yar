
rule Trojan_Win32_Ekstak_RS_MTB{
	meta:
		description = "Trojan:Win32/Ekstak.RS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_01_0 = {56 e8 0a 74 fb ff 8b f0 e9 } //5
		$a_01_1 = {40 00 00 40 5f 72 65 61 63 74 5f } //1
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}
rule Trojan_Win32_Ekstak_RS_MTB_2{
	meta:
		description = "Trojan:Win32/Ekstak.RS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_01_0 = {90 90 90 90 56 e8 1a 72 fb ff 8b f0 e9 } //5
		$a_01_1 = {40 00 00 40 2e 6d 61 69 6c } //1
		$a_01_2 = {40 00 00 40 2e 72 65 61 63 74 } //1 @䀀爮慥瑣
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=6
 
}