
rule Trojan_Win32_Emotet_GNF_MTB{
	meta:
		description = "Trojan:Win32/Emotet.GNF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {4f 55 63 63 6a 40 4e 63 72 38 4e 63 } //1 OUccj@Ncr8Nc
		$a_01_1 = {4c 48 32 53 62 48 39 59 } //1 LH2SbH9Y
		$a_01_2 = {40 2e 74 68 65 6d 69 64 61 } //1 @.themida
		$a_01_3 = {43 73 77 32 37 4c 30 } //1 Csw27L0
		$a_01_4 = {4f 53 6a 64 59 5a 63 } //1 OSjdYZc
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}