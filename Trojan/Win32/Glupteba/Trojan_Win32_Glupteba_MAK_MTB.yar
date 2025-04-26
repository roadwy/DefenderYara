
rule Trojan_Win32_Glupteba_MAK_MTB{
	meta:
		description = "Trojan:Win32/Glupteba.MAK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b 8d a8 fd ff ff 03 c8 c1 e8 05 89 45 [0-01] c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 8b 85 9c fd ff ff 01 45 90 1b 00 81 3d [0-06] 00 00 75 } //1
		$a_03_1 = {33 5d 74 89 3d [0-04] 89 9d ac fd ff ff 8b 85 ac fd ff ff 29 45 [0-01] 81 3d [0-06] 00 00 75 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}