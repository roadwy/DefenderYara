
rule Trojan_Win32_RedLine_RDBF_MTB{
	meta:
		description = "Trojan:Win32/RedLine.RDBF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 74 24 1c 8b 54 24 14 8b 46 24 8d 04 68 0f b7 0c 10 8b 46 1c 8d 04 88 8b 34 10 83 fb 10 72 3e 8d 4b 01 8b c7 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}