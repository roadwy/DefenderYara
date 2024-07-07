
rule Trojan_Win32_RedLine_RDAY_MTB{
	meta:
		description = "Trojan:Win32/RedLine.RDAY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b c6 83 e0 03 8a 88 90 01 04 32 0c 37 0f b6 1c 37 8d 04 19 88 04 37 90 00 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}