
rule Trojan_Win32_RedLine_RDAQ_MTB{
	meta:
		description = "Trojan:Win32/RedLine.RDAQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {89 75 d8 3b f7 73 ?? 8a 14 30 8b c6 83 e0 03 8a 88 ?? ?? ?? ?? 32 ca 0f b6 da 8d 04 19 8b 4d dc 88 04 31 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}