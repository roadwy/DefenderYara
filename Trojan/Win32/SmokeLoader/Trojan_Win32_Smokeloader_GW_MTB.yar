
rule Trojan_Win32_Smokeloader_GW_MTB{
	meta:
		description = "Trojan:Win32/Smokeloader.GW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 "
		
	strings :
		$a_01_0 = {03 d0 c1 e8 05 03 45 e8 03 ce 33 ca 33 c1 89 55 0c 89 4d 08 89 45 f0 8b 45 f0 } //10
		$a_01_1 = {01 45 fc 8b 45 08 8b 4d fc 31 08 c9 c2 08 00 55 8b ec 8b 4d 08 8b 01 89 45 08 8b 45 0c } //10
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10) >=20
 
}