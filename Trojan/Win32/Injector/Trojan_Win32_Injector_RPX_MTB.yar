
rule Trojan_Win32_Injector_RPX_MTB{
	meta:
		description = "Trojan:Win32/Injector.RPX!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {31 db 83 fa 29 83 f9 43 33 1c 0e 83 fb 50 83 fa 76 09 1c 08 83 f8 6d 81 fa aa 00 00 00 31 3c 08 83 fb 4d 81 f9 91 00 00 00 81 e9 42 02 00 00 83 f8 36 81 f9 97 00 00 00 81 c1 3d 02 00 00 3d f1 00 00 00 81 fa 8a 00 00 00 41 7d b2 81 f9 bf 00 00 00 81 fa db 00 00 00 ff e0 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}