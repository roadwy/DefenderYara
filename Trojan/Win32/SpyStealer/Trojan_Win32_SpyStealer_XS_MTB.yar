
rule Trojan_Win32_SpyStealer_XS_MTB{
	meta:
		description = "Trojan:Win32/SpyStealer.XS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_01_0 = {89 da 8b 4d f8 8b 45 0c 01 c8 8b 5d f8 8b 4d 0c 01 d9 0f b6 09 31 ca 88 10 83 45 } //10
	condition:
		((#a_01_0  & 1)*10) >=10
 
}