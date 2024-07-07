
rule Trojan_Win32_RedLine_RDCE_MTB{
	meta:
		description = "Trojan:Win32/RedLine.RDCE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {88 85 47 fc ff ff 0f b6 8d 47 fc ff ff c1 f9 02 0f b6 95 47 fc ff ff c1 e2 06 0b ca 88 8d 47 fc ff ff } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}