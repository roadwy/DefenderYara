
rule Trojan_Win32_Smokeloader_SPXV_MTB{
	meta:
		description = "Trojan:Win32/Smokeloader.SPXV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {33 c1 8b 4d 70 33 c7 2b f0 8b c6 c1 e8 05 89 b5 7c fe ff ff 03 ce 89 45 6c } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}