
rule Trojan_Win32_CoViper_RDA_MTB{
	meta:
		description = "Trojan:Win32/CoViper.RDA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {88 85 77 fe ff ff 0f b7 95 2c fd ff ff 0f b6 85 23 fe ff ff 33 c2 88 85 23 fe ff ff } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}