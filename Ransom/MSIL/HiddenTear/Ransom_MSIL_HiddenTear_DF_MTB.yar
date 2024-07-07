
rule Ransom_MSIL_HiddenTear_DF_MTB{
	meta:
		description = "Ransom:MSIL/HiddenTear.DF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_81_0 = {79 6f 75 72 20 66 69 6c 65 73 20 68 61 76 65 20 62 65 65 6e 20 65 6e 63 72 79 70 74 65 64 } //1 your files have been encrypted
		$a_81_1 = {2e 45 6e 63 72 79 70 74 65 64 } //1 .Encrypted
		$a_81_2 = {40 74 75 74 61 6e 6f 74 61 2e 63 6f 6d } //1 @tutanota.com
		$a_81_3 = {72 65 63 6f 76 65 72 79 65 6e 61 62 6c 65 64 20 6e 6f } //1 recoveryenabled no
		$a_81_4 = {62 6f 6f 74 73 74 61 74 75 73 70 6f 6c 69 63 79 20 69 67 6e 6f 72 65 61 6c 6c 66 61 69 6c 75 72 65 73 } //1 bootstatuspolicy ignoreallfailures
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1) >=5
 
}