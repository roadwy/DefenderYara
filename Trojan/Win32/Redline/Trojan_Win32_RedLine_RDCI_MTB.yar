
rule Trojan_Win32_RedLine_RDCI_MTB{
	meta:
		description = "Trojan:Win32/RedLine.RDCI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {f7 75 f4 0f b6 92 ?? ?? ?? ?? 33 ca 88 4d ff } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}