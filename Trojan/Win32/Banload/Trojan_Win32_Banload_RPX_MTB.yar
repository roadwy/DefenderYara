
rule Trojan_Win32_Banload_RPX_MTB{
	meta:
		description = "Trojan:Win32/Banload.RPX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {83 c0 04 83 c0 14 56 8b f0 8d 7c 24 28 b9 38 00 00 00 f3 a5 5e 6a 40 68 00 30 00 00 8b 5c 24 64 53 6a 00 ff 56 04 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}