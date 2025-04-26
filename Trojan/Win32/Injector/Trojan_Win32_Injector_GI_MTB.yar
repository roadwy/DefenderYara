
rule Trojan_Win32_Injector_GI_MTB{
	meta:
		description = "Trojan:Win32/Injector.GI!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 02 00 00 "
		
	strings :
		$a_01_0 = {be 00 00 00 00 81 c2 01 00 00 00 bf 21 29 6d dd 09 ff 31 18 01 ff 01 d2 81 c0 02 00 00 00 21 d7 09 d7 ba 46 b4 0d 90 39 c8 } //1
		$a_01_1 = {be 00 00 00 00 01 c3 81 c3 7d ab 0f 17 b8 86 3b c0 52 01 c0 81 e8 2a 4c f3 36 31 17 48 09 db 48 81 c7 02 00 00 00 f7 d3 29 d8 39 cf } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=1
 
}