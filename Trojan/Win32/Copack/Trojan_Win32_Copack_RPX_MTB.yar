
rule Trojan_Win32_Copack_RPX_MTB{
	meta:
		description = "Trojan:Win32/Copack.RPX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 1c 24 83 c4 04 e8 25 00 00 00 01 c7 21 c7 31 1e 68 ?? ?? ?? ?? 58 46 21 f8 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}