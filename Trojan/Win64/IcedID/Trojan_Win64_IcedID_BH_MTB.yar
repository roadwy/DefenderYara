
rule Trojan_Win64_IcedID_BH_MTB{
	meta:
		description = "Trojan:Win64/IcedID.BH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 08 00 00 "
		
	strings :
		$a_01_0 = {43 6e 47 66 39 2e 64 6c 6c } //5 CnGf9.dll
		$a_01_1 = {48 31 4c 38 58 74 43 59 } //1 H1L8XtCY
		$a_01_2 = {4a 59 41 30 45 4a 73 51 } //1 JYA0EJsQ
		$a_01_3 = {4b 78 45 43 48 48 35 6d 4a 35 } //1 KxECHH5mJ5
		$a_01_4 = {4e 33 4a 57 37 50 77 44 42 66 } //1 N3JW7PwDBf
		$a_01_5 = {4f 52 4f 4f 45 4c 67 } //1 OROOELg
		$a_01_6 = {58 71 31 69 47 52 72 71 4a 54 6e } //1 Xq1iGRrqJTn
		$a_01_7 = {61 50 62 43 50 34 34 6d 32 61 6e } //1 aPbCP44m2an
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=12
 
}