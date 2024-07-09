
rule Trojan_Win32_RedLine_RDBA_MTB{
	meta:
		description = "Trojan:Win32/RedLine.RDBA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {8a 84 3c 8c 00 00 00 88 84 34 8c 00 00 00 88 8c 3c 8c 00 00 00 0f b6 84 34 8c 00 00 00 03 c2 0f b6 c0 8a 84 04 8c 00 00 00 30 83 ?? ?? ?? ?? 43 81 fb 00 bc 02 00 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}