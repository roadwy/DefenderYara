
rule Trojan_Win32_FowlGaze_A_MTB{
	meta:
		description = "Trojan:Win32/FowlGaze.A!MTB,SIGNATURE_TYPE_PEHSTR,14 00 14 00 02 00 00 "
		
	strings :
		$a_01_0 = {0f b7 85 b8 fe ff ff 35 95 07 00 00 88 85 78 fe ff ff 8d 85 78 fe ff ff } //10
		$a_01_1 = {88 8c 05 f8 fe ff ff 0f b6 95 f4 fc ff ff 8b 85 ec fe ff ff 0f b6 8c 05 f8 fe ff ff 33 ca 8b 95 ec fe ff ff 88 8c 15 f8 fe ff ff } //10
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10) >=20
 
}