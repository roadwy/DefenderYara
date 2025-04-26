
rule Trojan_Win32_Roxer_EC_MTB{
	meta:
		description = "Trojan:Win32/Roxer.EC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 02 00 00 "
		
	strings :
		$a_01_0 = {88 8d f8 fe ff ff 8a cb c1 ea 03 0f be c2 6b c0 19 69 db 0d 66 19 00 2a c8 b8 1f 85 eb 51 81 c3 5c f3 6e 3c 80 c1 61 f7 e3 88 8d f9 fe ff ff } //7
		$a_01_1 = {69 c9 0d 66 19 00 33 d2 6a 19 5f 81 c1 5c f3 6e 3c 8b c1 f7 f7 80 c2 61 88 94 35 f4 fd ff ff } //7
	condition:
		((#a_01_0  & 1)*7+(#a_01_1  & 1)*7) >=7
 
}