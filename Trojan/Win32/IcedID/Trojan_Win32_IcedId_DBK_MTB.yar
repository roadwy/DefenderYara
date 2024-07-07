
rule Trojan_Win32_IcedId_DBK_MTB{
	meta:
		description = "Trojan:Win32/IcedId.DBK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_02_0 = {6a 01 5d 55 56 56 50 ff 15 90 01 04 85 c0 5b 75 37 6a 08 55 56 8d 44 24 18 56 50 ff 15 90 1b 00 85 c0 90 00 } //1
		$a_81_1 = {4f 47 75 72 31 78 50 70 47 78 73 58 57 63 53 } //1 OGur1xPpGxsXWcS
	condition:
		((#a_02_0  & 1)*1+(#a_81_1  & 1)*1) >=1
 
}