
rule Trojan_Win32_Injector_B_MTB{
	meta:
		description = "Trojan:Win32/Injector.B!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {8a 54 39 ec 88 94 0d ?? ?? ff ff 41 83 f9 ?? 72 ef } //1
		$a_00_1 = {89 01 40 83 c1 04 3d 00 01 00 00 7c f3 } //1
		$a_00_2 = {81 e7 ff 00 00 00 89 7c b4 14 8b 5c 8c 14 03 df 81 e3 ff 00 00 80 79 08 4b 81 cb 00 ff ff ff 43 8a 5c 9c 14 30 1c 2a 42 3b d0 72 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}