
rule Trojan_Win32_BroomStick_Z_MTB{
	meta:
		description = "Trojan:Win32/BroomStick.Z!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_00_0 = {3b f7 7c db 5f 5e 5b } //1
		$a_00_1 = {8b 85 10 ff ff ff 8b 00 8b 70 18 8d 45 a8 } //1
		$a_00_2 = {85 c0 74 25 8d 3c 40 03 ff 83 ef 06 8b d3 } //1
		$a_00_3 = {8b 5d d8 ff 00 33 f6 8b 00 0f b6 08 } //1
		$a_02_4 = {8b ce ff 15 [0-20] 8b cf ff d6 8b 85 28 ff ff ff } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_02_4  & 1)*1) >=5
 
}