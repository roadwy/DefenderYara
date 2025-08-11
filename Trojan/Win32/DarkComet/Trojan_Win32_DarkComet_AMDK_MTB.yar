
rule Trojan_Win32_DarkComet_AMDK_MTB{
	meta:
		description = "Trojan:Win32/DarkComet.AMDK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8d 95 fc fb ff ff 52 8d 85 f4 fb ff ff 50 8d 4d fc 51 8d 95 f0 fb ff ff 52 68 00 04 00 00 8d 85 f0 f7 ff ff 50 68 e4 22 41 00 ff 15 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}