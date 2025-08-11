
rule Trojan_Win32_Guloader_RKF_MTB{
	meta:
		description = "Trojan:Win32/Guloader.RKF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_81_0 = {62 72 6e 64 62 6f 72 65 72 6d 65 73 74 65 72 } //1 brndborermester
		$a_81_1 = {73 6b 72 61 6c 64 65 72 67 72 69 6e 65 72 } //1 skraldergriner
		$a_81_2 = {61 70 70 65 74 69 73 65 6d 65 6e 74 73 } //1 appetisements
		$a_81_3 = {73 74 72 69 64 73 68 61 6e 64 73 6b 65 72 6e 65 } //1 stridshandskerne
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=4
 
}