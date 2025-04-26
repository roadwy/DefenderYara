
rule Trojan_Win32_IcedID_MD_MTB{
	meta:
		description = "Trojan:Win32/IcedID.MD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 02 00 00 "
		
	strings :
		$a_01_0 = {cc 31 00 09 c0 41 1d 54 b6 58 2e 4b 92 83 65 fc 53 45 9f 60 20 fb 94 52 b7 e3 b6 49 83 52 8e e5 2b c7 19 76 3a 4f } //5
		$a_01_1 = {42 00 4f 00 58 00 } //2 BOX
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*2) >=7
 
}