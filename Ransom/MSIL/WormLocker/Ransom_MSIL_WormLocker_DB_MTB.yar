
rule Ransom_MSIL_WormLocker_DB_MTB{
	meta:
		description = "Ransom:MSIL/WormLocker.DB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_81_0 = {72 61 6e 73 6f 6d 5f 76 6f 69 63 65 2e 76 62 73 } //1 ransom_voice.vbs
		$a_81_1 = {67 65 74 5f 43 75 72 72 65 6e 74 44 6f 6d 61 69 6e } //1 get_CurrentDomain
		$a_81_2 = {57 6f 72 6d 4c 6f 63 6b 65 72 } //1 WormLocker
		$a_81_3 = {63 79 62 65 72 77 61 72 65 } //1 cyberware
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=4
 
}