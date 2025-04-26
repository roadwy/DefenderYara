
rule Trojan_BAT_AgentTesla_NTD_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NTD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 "
		
	strings :
		$a_81_0 = {66 73 64 73 64 64 66 64 73 73 66 66 66 66 64 } //1 fsdsddfdssffffd
		$a_81_1 = {73 65 64 64 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 64 66 66 65 78 65 } //1 seddfffffffffffffffffdffexe
		$a_81_2 = {53 68 6f 72 74 50 64 64 64 64 64 64 64 64 64 64 64 64 64 64 64 64 66 64 64 64 72 6f 63 65 73 73 20 43 6f 6d 70 6c 65 74 65 64 } //1 ShortPddddddddddddddddfdddrocess Completed
		$a_81_3 = {67 64 64 67 64 6c 73 66 66 73 64 66 73 64 73 66 64 6c 73 67 73 64 73 64 66 68 73 67 } //1 gddgdlsffsdfsdsfdlsgsdsdfhsg
		$a_81_4 = {64 72 64 66 65 66 66 73 73 64 64 64 66 73 6c 6f 73 66 73 64 66 65 67 } //1 drdfeffssdddfslosfsdfeg
		$a_81_5 = {66 73 64 64 64 64 73 66 73 66 66 66 73 66 73 66 73 64 64 66 64 66 } //1 fsddddsfsfffsfsfsddfdf
		$a_81_6 = {6c 70 66 73 64 66 41 64 64 73 61 64 72 65 73 73 } //1 lpfsdfAddsadress
		$a_81_7 = {68 50 66 64 73 66 72 6f 64 73 63 65 73 73 } //1 hPfdsfrodscess
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1) >=8
 
}