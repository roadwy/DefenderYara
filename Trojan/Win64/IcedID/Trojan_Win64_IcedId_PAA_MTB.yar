
rule Trojan_Win64_IcedId_PAA_MTB{
	meta:
		description = "Trojan:Win64/IcedId.PAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {99 b9 33 00 00 00 f7 f9 48 63 ca 48 8b 84 24 ?? ?? ?? ?? 0f b6 04 08 8b d7 33 d0 48 63 8c 24 ?? ?? ?? ?? 48 8b 84 24 ?? ?? ?? ?? 88 14 08 eb } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win64_IcedId_PAA_MTB_2{
	meta:
		description = "Trojan:Win64/IcedId.PAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 0d 00 00 "
		
	strings :
		$a_81_0 = {44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 } //10 DllRegisterServer
		$a_81_1 = {41 71 48 74 6c 6e } //1 AqHtln
		$a_81_2 = {45 6e 7a 53 62 6f 48 54 46 47 61 44 6f 6f 47 64 } //1 EnzSboHTFGaDooGd
		$a_81_3 = {48 73 49 58 67 59 6f } //1 HsIXgYo
		$a_81_4 = {53 78 52 57 71 6f 70 } //1 SxRWqop
		$a_81_5 = {59 4b 4e 45 76 4d 79 67 54 64 7a 4d } //1 YKNEvMygTdzM
		$a_81_6 = {63 53 58 43 4a 54 68 66 6f 4b 45 } //1 cSXCJThfoKE
		$a_81_7 = {41 66 62 65 42 55 57 51 79 76 66 41 } //1 AfbeBUWQyvfA
		$a_81_8 = {43 67 4b 55 79 58 63 4f 57 63 7a 69 48 77 4e } //1 CgKUyXcOWcziHwN
		$a_81_9 = {49 49 79 74 6a 48 56 50 56 4a 54 48 4d 64 6f 66 } //1 IIytjHVPVJTHMdof
		$a_81_10 = {4d 65 4e 4c 73 42 76 4c 49 55 } //1 MeNLsBvLIU
		$a_81_11 = {52 47 76 4e 62 62 72 74 52 43 41 } //1 RGvNbbrtRCA
		$a_81_12 = {59 58 6c 6d 57 46 68 4c 4e 4e 49 55 6c 6a } //1 YXlmWFhLNNIUlj
	condition:
		((#a_81_0  & 1)*10+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1+(#a_81_8  & 1)*1+(#a_81_9  & 1)*1+(#a_81_10  & 1)*1+(#a_81_11  & 1)*1+(#a_81_12  & 1)*1) >=15
 
}