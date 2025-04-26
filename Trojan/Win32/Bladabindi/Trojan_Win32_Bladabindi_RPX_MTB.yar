
rule Trojan_Win32_Bladabindi_RPX_MTB{
	meta:
		description = "Trojan:Win32/Bladabindi.RPX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {00 04 78 ff 24 03 00 0d 1c 00 04 00 fc c8 1b 05 00 04 72 ff 04 74 ff 05 00 00 24 01 00 0d 14 00 02 00 08 74 ff 0d b8 00 06 00 6b 72 ff } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}