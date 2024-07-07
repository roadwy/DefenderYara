
rule Trojan_BAT_Formbook_RPH_MTB{
	meta:
		description = "Trojan:BAT/Formbook.RPH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {4b 00 6d 00 78 00 64 00 76 00 77 00 6f 00 } //1 Kmxdvwo
		$a_01_1 = {50 00 79 00 71 00 61 00 6f 00 63 00 75 00 61 00 6a 00 6d 00 2e 00 4a 00 6f 00 72 00 6e 00 68 00 77 00 64 00 70 00 65 00 6a 00 } //1 Pyqaocuajm.Jornhwdpej
		$a_01_2 = {53 69 70 61 72 69 73 20 6f 6e 61 79 69 } //1 Siparis onayi
		$a_01_3 = {48 72 68 69 6b 6f } //1 Hrhiko
		$a_01_4 = {73 6d 65 74 68 6f 64 5f 34 } //1 smethod_4
		$a_01_5 = {47 5a 69 70 53 74 72 65 61 6d } //1 GZipStream
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}
rule Trojan_BAT_Formbook_RPH_MTB_2{
	meta:
		description = "Trojan:BAT/Formbook.RPH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 07 00 00 "
		
	strings :
		$a_03_0 = {6d 00 79 00 70 00 75 00 72 00 65 00 2e 00 30 00 30 00 30 00 77 00 65 00 62 00 68 00 6f 00 73 00 74 00 61 00 70 00 70 00 2e 00 63 00 6f 00 6d 00 2f 00 70 00 75 00 72 00 65 00 90 02 40 2e 00 6a 00 70 00 67 00 90 00 } //1
		$a_01_1 = {47 6f 6f 67 6c 65 20 55 70 64 61 74 65 20 53 65 74 75 70 } //1 Google Update Setup
		$a_01_2 = {57 65 62 52 65 71 75 65 73 74 } //1 WebRequest
		$a_01_3 = {54 6f 41 72 72 61 79 } //1 ToArray
		$a_01_4 = {52 65 61 64 42 79 74 65 73 } //1 ReadBytes
		$a_01_5 = {44 79 6e 61 6d 69 63 49 6e 76 6f 6b 65 } //1 DynamicInvoke
		$a_01_6 = {47 65 74 54 79 70 65 73 } //1 GetTypes
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=6
 
}
rule Trojan_BAT_Formbook_RPH_MTB_3{
	meta:
		description = "Trojan:BAT/Formbook.RPH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {4c 00 76 00 72 00 6a 00 69 00 6c 00 65 00 67 00 71 00 2e 00 46 00 73 00 6a 00 65 00 67 00 63 00 73 00 6f 00 77 00 70 00 79 00 78 00 73 00 68 00 71 00 64 00 69 00 } //1 Lvrjilegq.Fsjegcsowpyxshqdi
		$a_01_1 = {4d 00 73 00 6d 00 6d 00 64 00 72 00 76 00 72 00 63 00 76 00 62 00 6a 00 73 00 6c 00 } //1 Msmmdrvrcvbjsl
		$a_01_2 = {31 00 38 00 35 00 2e 00 32 00 32 00 32 00 2e 00 35 00 38 00 2e 00 35 00 36 00 } //1 185.222.58.56
		$a_01_3 = {49 00 62 00 7a 00 63 00 62 00 6d 00 6e 00 67 00 2e 00 70 00 6e 00 67 00 } //1 Ibzcbmng.png
		$a_01_4 = {47 00 65 00 74 00 42 00 79 00 74 00 65 00 41 00 72 00 72 00 61 00 79 00 41 00 73 00 79 00 6e 00 63 00 } //1 GetByteArrayAsync
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}