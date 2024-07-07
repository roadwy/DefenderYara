
rule Trojan_BAT_AgentTesla_MTQ_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.MTQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_02_0 = {69 6a 5d d4 91 06 07 06 8e 69 6a 5d d4 91 61 28 90 01 02 00 0a 02 07 17 6a 58 02 8e 69 6a 5d d4 91 28 90 01 02 00 0a 59 20 00 01 00 00 58 20 00 01 00 00 5e 90 00 } //10
	condition:
		((#a_02_0  & 1)*10) >=10
 
}
rule Trojan_BAT_AgentTesla_MTQ_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.MTQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1a 00 1a 00 0e 00 00 "
		
	strings :
		$a_80_0 = {50 54 53 6f 66 74 5f 4d 61 69 6c 53 65 72 76 65 72 2e 4f 66 66 69 63 65 72 } //PTSoft_MailServer.Officer  2
		$a_80_1 = {41 73 79 6d 6d 65 74 72 69 63 } //Asymmetric  2
		$a_80_2 = {50 54 53 6f 66 74 5f 4d 61 69 6c 53 65 72 76 65 72 2e 52 65 73 6f 75 72 63 65 73 } //PTSoft_MailServer.Resources  2
		$a_80_3 = {45 76 65 6e 74 4f 70 63 6f 64 65 } //EventOpcode  2
		$a_80_4 = {42 69 74 6d 61 70 } //Bitmap  2
		$a_80_5 = {45 6d 61 69 6c 49 6e 66 6f } //EmailInfo  2
		$a_80_6 = {46 69 6c 65 53 79 73 74 65 6d 49 6e 66 6f } //FileSystemInfo  2
		$a_80_7 = {4d 69 6e 6f 72 56 65 72 73 69 6f 6e } //MinorVersion  2
		$a_80_8 = {43 72 65 61 74 65 5f 5f 49 6e 73 74 61 6e 63 65 5f 5f } //Create__Instance__  2
		$a_80_9 = {50 4f 50 33 53 65 72 76 65 72 } //POP3Server  2
		$a_80_10 = {42 65 73 74 46 69 74 4d 61 70 70 69 6e 67 41 74 74 72 69 62 75 74 65 2e 45 6e 75 6d 65 72 61 74 6f 72 53 69 6d 70 6c 65 } //BestFitMappingAttribute.EnumeratorSimple  2
		$a_80_11 = {47 65 74 50 69 78 65 6c } //GetPixel  2
		$a_80_12 = {73 65 63 75 72 69 74 79 2e 63 65 72 } //security.cer  2
		$a_80_13 = {6d 65 73 73 61 67 65 2e 74 78 74 } //message.txt  2
	condition:
		((#a_80_0  & 1)*2+(#a_80_1  & 1)*2+(#a_80_2  & 1)*2+(#a_80_3  & 1)*2+(#a_80_4  & 1)*2+(#a_80_5  & 1)*2+(#a_80_6  & 1)*2+(#a_80_7  & 1)*2+(#a_80_8  & 1)*2+(#a_80_9  & 1)*2+(#a_80_10  & 1)*2+(#a_80_11  & 1)*2+(#a_80_12  & 1)*2+(#a_80_13  & 1)*2) >=26
 
}