
rule Trojan_Win32_Zenpack_NO_MTB{
	meta:
		description = "Trojan:Win32/Zenpack.NO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {33 fa 81 3d 90 01 08 c7 05 90 01 08 75 90 0a 2a 00 8b 4d 90 01 01 8b 55 90 01 01 8b f3 c1 ee 05 03 75 90 01 01 03 f9 03 d3 90 00 } //1
		$a_03_1 = {33 f3 33 f7 29 75 90 01 01 81 3d 90 01 08 75 90 0a 50 00 8b 75 90 01 01 c1 ee 05 03 75 90 01 01 81 3d 90 01 08 c7 05 90 01 08 c7 05 90 01 04 ff ff ff ff 75 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}