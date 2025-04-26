
rule Trojan_Win32_PonyStealer_PA_MTB{
	meta:
		description = "Trojan:Win32/PonyStealer.PA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_00_0 = {59 8b 0e 56 } //1
		$a_00_1 = {5e 29 de 51 } //1
		$a_00_2 = {59 31 c1 56 } //1
		$a_00_3 = {5e 89 0c 1a 56 } //1
		$a_02_4 = {5e 85 db 0f 85 ?? ?? ff ff } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_02_4  & 1)*1) >=5
 
}