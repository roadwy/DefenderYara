
rule Trojan_Win32_IcedId_DEJ_MTB{
	meta:
		description = "Trojan:Win32/IcedId.DEJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_02_0 = {83 c4 0c 6a 00 6a 01 6a 00 6a 00 8d 55 90 01 01 52 ff 15 90 01 04 85 c0 75 40 6a 08 6a 01 6a 00 6a 00 8d 45 90 1b 00 50 ff 15 90 1b 01 85 c0 90 00 } //1
		$a_81_1 = {45 65 53 56 48 43 42 38 66 41 38 34 69 36 45 } //1 EeSVHCB8fA84i6E
	condition:
		((#a_02_0  & 1)*1+(#a_81_1  & 1)*1) >=1
 
}