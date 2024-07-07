
rule Trojan_Win32_Guloader_SPQS_MTB{
	meta:
		description = "Trojan:Win32/Guloader.SPQS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_81_0 = {52 65 76 69 73 69 74 73 40 54 6f 74 61 6c 69 74 65 74 65 6e 2e 46 72 69 31 20 30 } //1 Revisits@Totaliteten.Fri1 0
		$a_81_1 = {54 61 75 72 6f 6d 61 63 68 69 61 6e 20 54 73 65 6e 61 61 6c 65 73 20 31 } //1 Tauromachian Tsenaales 1
		$a_81_2 = {50 72 6f 74 68 65 74 65 6c 79 31 27 30 25 } //1 Prothetely1'0%
		$a_81_3 = {50 72 6f 74 68 65 74 65 6c 79 30 } //1 Prothetely0
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=4
 
}