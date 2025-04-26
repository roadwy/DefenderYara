
rule Trojan_Win32_Qukart_GMA_MTB{
	meta:
		description = "Trojan:Win32/Qukart.GMA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {6e 64 6a 76 64 41 57 62 37 } //1 ndjvdAWb7
		$a_01_1 = {77 5a 45 42 73 56 7a 6d 6b } //1 wZEBsVzmk
		$a_01_2 = {50 71 4a 77 78 52 66 73 68 } //1 PqJwxRfsh
		$a_01_3 = {74 47 79 6a 50 69 45 55 34 } //1 tGyjPiEU4
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}