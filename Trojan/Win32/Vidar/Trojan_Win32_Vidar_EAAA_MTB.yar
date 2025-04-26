
rule Trojan_Win32_Vidar_EAAA_MTB{
	meta:
		description = "Trojan:Win32/Vidar.EAAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b b4 24 18 01 00 00 32 0c 16 30 d9 88 0c 16 42 39 94 24 1c 01 00 00 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}