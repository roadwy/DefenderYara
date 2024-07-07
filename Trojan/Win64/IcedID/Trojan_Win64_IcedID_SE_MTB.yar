
rule Trojan_Win64_IcedID_SE_MTB{
	meta:
		description = "Trojan:Win64/IcedID.SE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {8b 0c 81 31 0a 49 8b 88 90 01 04 49 90 01 02 48 90 01 03 49 90 01 02 41 8b 88 90 01 04 81 e1 90 00 } //1
		$a_03_1 = {49 8b 88 d0 90 01 03 48 35 90 01 04 48 29 81 90 01 04 41 90 01 06 ff c0 90 01 01 41 f7 b8 90 01 04 41 90 00 } //1
		$a_00_2 = {44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 } //1 DllRegisterServer
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}