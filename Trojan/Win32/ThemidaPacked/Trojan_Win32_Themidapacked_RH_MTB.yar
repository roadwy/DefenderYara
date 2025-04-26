
rule Trojan_Win32_Themidapacked_RH_MTB{
	meta:
		description = "Trojan:Win32/Themidapacked.RH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 05 00 00 "
		
	strings :
		$a_81_0 = {55 5a 6b 6b 6d 6d 6b 6b 58 3a } //2 UZkkmmkkX:
		$a_81_1 = {21 29 2e 2f 2f 45 45 46 46 46 48 46 48 48 48 46 48 3e 46 44 44 2e 2b 23 } //1 !).//EEFFFHFHHHFH>FDD.+#
		$a_81_2 = {5f 21 36 68 6d 73 73 72 74 72 72 72 74 71 71 6d 49 25 } //1 _!6hmssrtrrrtqqmI%
		$a_81_3 = {3b 46 53 58 58 59 59 58 58 52 2e } //1 ;FSXXYYXXR.
		$a_81_4 = {53 70 79 2e 65 78 65 } //2 Spy.exe
	condition:
		((#a_81_0  & 1)*2+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*2) >=6
 
}