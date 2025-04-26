
rule Trojan_Win32_SmokeLoader_BF_MTB{
	meta:
		description = "Trojan:Win32/SmokeLoader.BF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 "
		
	strings :
		$a_01_0 = {01 f3 83 ec 04 89 14 24 ba 00 00 00 00 01 da 31 02 5a 5b 53 } //4
	condition:
		((#a_01_0  & 1)*4) >=4
 
}