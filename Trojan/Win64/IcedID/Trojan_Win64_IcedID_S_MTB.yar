
rule Trojan_Win64_IcedID_S_MTB{
	meta:
		description = "Trojan:Win64/IcedID.S!MTB,SIGNATURE_TYPE_PEHSTR_EXT,15 00 15 00 03 00 00 "
		
	strings :
		$a_01_0 = {8a ca 48 8b d0 48 d3 ca 49 33 d0 4b 87 94 fe b8 5b 02 00 eb 2d } //10
		$a_02_1 = {41 8b c2 b9 40 00 00 00 83 e0 3f 2b c8 48 d3 cf 49 33 fa 4b 87 bc fe 90 01 04 33 c0 48 8b 5c 24 50 48 8b 6c 24 58 48 8b 74 24 60 90 00 } //10
		$a_01_2 = {44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 } //1 DllRegisterServer
	condition:
		((#a_01_0  & 1)*10+(#a_02_1  & 1)*10+(#a_01_2  & 1)*1) >=21
 
}