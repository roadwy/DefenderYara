
rule Trojan_Win32_RedLineStealer_QP_MTB{
	meta:
		description = "Trojan:Win32/RedLineStealer.QP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 "
		
	strings :
		$a_02_0 = {8b 85 1c fd ff ff 01 45 fc 8b 85 90 01 04 03 c7 33 f0 81 3d 90 01 08 75 1b 90 00 } //10
		$a_02_1 = {8b 85 2c fd ff ff 03 cb 33 c1 31 45 fc 81 3d 90 01 04 a3 01 00 00 75 08 90 00 } //10
	condition:
		((#a_02_0  & 1)*10+(#a_02_1  & 1)*10) >=20
 
}