
rule Trojan_BAT_Azorult_MK_MTB{
	meta:
		description = "Trojan:BAT/Azorult.MK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_80_0 = {52 65 6d 6f 74 65 50 72 6f 70 65 72 74 79 48 6f 6c 64 65 72 41 74 74 72 69 62 75 74 65 21 } //RemotePropertyHolderAttribute!  1
		$a_80_1 = {53 74 61 63 6b 42 65 68 61 76 69 6f 75 72 } //StackBehaviour  1
		$a_80_2 = {49 43 68 61 6e 6e 65 6c 52 65 63 65 69 76 65 72 } //IChannelReceiver  1
		$a_80_3 = {52 65 6d 6f 74 69 6e 67 4d 65 74 68 6f 64 43 61 63 68 65 64 44 61 74 61 20 69 6e 20 73 65 6e 73 6f 20 64 65 63 72 65 73 63 65 6e 74 65 3a } //RemotingMethodCachedData in senso decrescente:  1
		$a_80_4 = {53 54 4f 52 45 5f 41 53 53 45 4d 42 4c 59 5f 46 49 4c 45 5f 53 54 41 54 55 53 5f 46 4c 41 47 53 20 53 54 4f 52 45 5f 41 53 53 45 4d 42 4c 59 5f 46 49 4c 45 5f 53 54 41 54 55 53 5f 46 4c 41 47 53 20 41 73 63 3a } //STORE_ASSEMBLY_FILE_STATUS_FLAGS STORE_ASSEMBLY_FILE_STATUS_FLAGS Asc:  1
		$a_80_5 = {4e 6f 72 6d 61 6c 69 7a 61 74 69 6f 6e 20 4e 6f 72 6d 61 6c 69 7a 61 74 69 6f 6e 20 53 74 72 61 6e 6f 3a } //Normalization Normalization Strano:  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1) >=6
 
}