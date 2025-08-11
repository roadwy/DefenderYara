
rule Trojan_Win32_OffLoader_GPPC_MTB{
	meta:
		description = "Trojan:Win32/OffLoader.GPPC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 "
		
	strings :
		$a_03_0 = {72 44 6c 50 74 53 cd e6 d7 7b 0b 2a 01 00 00 00 ?? ?? ?? 00 ?? ?? ?? 00 00 60 33 00 33 a5 c9 0f 3a 46 0e } //4
	condition:
		((#a_03_0  & 1)*4) >=4
 
}