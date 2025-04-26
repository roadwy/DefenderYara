
rule Trojan_Win32_GuLoader_RBO_MTB{
	meta:
		description = "Trojan:Win32/GuLoader.RBO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_81_0 = {62 61 6c 6b 61 6e 6c 61 6e 64 20 70 61 72 61 6d 65 74 65 72 66 72 65 6d 73 74 69 6c 6c 69 6e 67 65 72 73 20 66 6f 72 61 6e 6e 76 6e 74 } //1 balkanland parameterfremstillingers forannvnt
		$a_81_1 = {73 70 69 6c 64 65 76 61 6e 64 73 62 65 6b 65 6e 64 74 67 72 65 6c 73 65 6e 73 20 6e 6f 6e 6c 69 71 75 69 64 61 74 69 6e 67 } //1 spildevandsbekendtgrelsens nonliquidating
		$a_81_2 = {6b 76 6c 6c 65 72 6e 65 73 20 73 70 6f 6e 64 69 61 73 20 6d 6f 6c 65 6e 64 69 6e 61 72 79 } //1 kvllernes spondias molendinary
		$a_81_3 = {62 61 63 6b 62 75 72 6e } //1 backburn
		$a_81_4 = {61 6e 67 69 6f 6e 6f 6d 61 2e 65 78 65 } //1 angionoma.exe
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1) >=5
 
}