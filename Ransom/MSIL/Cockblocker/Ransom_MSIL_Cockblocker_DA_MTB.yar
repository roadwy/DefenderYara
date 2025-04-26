
rule Ransom_MSIL_Cockblocker_DA_MTB{
	meta:
		description = "Ransom:MSIL/Cockblocker.DA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 05 00 00 "
		
	strings :
		$a_81_0 = {48 69 20 52 65 76 65 72 73 65 69 6e 67 20 45 6e 67 69 6e 65 65 72 73 21 20 49 20 68 61 74 65 20 70 65 6f 70 6c 65 20 77 68 6f 20 61 72 65 20 74 6f 6f 20 6c 61 7a 79 20 74 6f 20 6d 61 6b 65 20 74 68 65 69 72 20 6f 77 6e 20 72 61 6e 73 6f 6d 77 61 72 65 } //1 Hi Reverseing Engineers! I hate people who are too lazy to make their own ransomware
		$a_81_1 = {43 6c 6f 73 65 20 76 69 61 20 54 61 73 6b 4d 67 72 20 6e 6f 77 20 69 66 20 79 6f 75 20 64 6f 20 6e 6f 74 20 77 61 6e 74 20 79 6f 75 72 20 66 69 6c 65 73 20 65 6e 63 72 79 70 74 65 64 21 } //1 Close via TaskMgr now if you do not want your files encrypted!
		$a_81_2 = {52 61 6e 73 6f 6d 77 61 72 65 44 69 73 70 6c 61 79 } //1 RansomwareDisplay
		$a_81_3 = {43 6f 63 6b 62 6c 6f 63 6b 65 72 } //1 Cockblocker
		$a_81_4 = {69 74 27 73 20 6e 6f 74 20 66 75 63 6b 69 6e 67 20 52 61 7a 79 } //1 it's not fucking Razy
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1) >=4
 
}