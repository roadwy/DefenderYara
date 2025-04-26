
rule Trojan_Win32_Guloader_SLA_MTB{
	meta:
		description = "Trojan:Win32/Guloader.SLA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_81_0 = {55 6e 64 65 72 73 74 61 74 65 6d 65 6e 74 65 6e 73 } //1 Understatementens
		$a_81_1 = {72 61 64 69 6f 6c 69 74 69 63 20 74 68 69 6f 6e 69 6e 65 73 } //1 radiolitic thionines
		$a_81_2 = {66 6a 65 72 6e 6b 6f 6e 74 72 6f 6c 6c 65 72 73 2e 68 69 64 } //1 fjernkontrollers.hid
		$a_81_3 = {69 72 72 65 73 6f 6c 75 62 6c 65 6e 65 73 73 2e 68 6a 65 } //1 irresolubleness.hje
		$a_81_4 = {70 61 61 73 6b 6e 6e 65 6e 64 65 20 61 70 70 6c 65 67 72 6f 77 65 72 } //1 paasknnende applegrower
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1) >=5
 
}