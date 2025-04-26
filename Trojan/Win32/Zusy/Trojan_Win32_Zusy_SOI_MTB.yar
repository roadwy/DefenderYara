
rule Trojan_Win32_Zusy_SOI_MTB{
	meta:
		description = "Trojan:Win32/Zusy.SOI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {ff 15 d8 ab 40 00 8d 85 f0 fc ff ff 48 8d 49 00 8a 48 01 40 84 c9 75 f8 66 8b 0d 1c 72 40 00 8a 15 1e 72 40 00 66 89 08 88 50 02 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}