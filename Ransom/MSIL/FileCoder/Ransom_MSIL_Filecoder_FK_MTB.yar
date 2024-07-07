
rule Ransom_MSIL_Filecoder_FK_MTB{
	meta:
		description = "Ransom:MSIL/Filecoder.FK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_81_0 = {47 61 74 65 77 61 79 49 50 41 64 64 72 65 73 73 49 6e 66 6f 72 6d 61 74 69 6f 6e 43 6f 6c 6c 65 63 74 69 6f 6e } //1 GatewayIPAddressInformationCollection
		$a_81_1 = {6d 40 61 69 40 6c 2e 40 72 6f 40 74 62 40 6c 61 40 75 2e 40 65 75 40 } //1 m@ai@l.@ro@tb@la@u.@eu@
		$a_81_2 = {43 75 72 40 72 65 6e 40 74 56 65 72 40 73 69 6f 6e 5c 52 40 75 6e } //1 Cur@ren@tVer@sion\R@un
		$a_81_3 = {75 70 6c 6f 61 64 66 69 6c 65 } //1 uploadfile
		$a_81_4 = {47 65 74 44 69 72 65 63 74 6f 72 69 65 73 } //1 GetDirectories
		$a_81_5 = {47 65 74 45 78 74 65 6e 73 69 6f 6e } //1 GetExtension
		$a_81_6 = {52 65 70 6c 61 63 65 } //1 Replace
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1) >=7
 
}