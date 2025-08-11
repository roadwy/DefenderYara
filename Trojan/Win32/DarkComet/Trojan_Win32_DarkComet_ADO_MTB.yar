
rule Trojan_Win32_DarkComet_ADO_MTB{
	meta:
		description = "Trojan:Win32/DarkComet.ADO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 45 14 8b 55 08 03 c2 89 45 f8 8b 01 03 45 0c 8b ce 99 f7 f9 8b 45 f8 8a 8c 95 94 fb ff ff 30 08 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}