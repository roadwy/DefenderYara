
rule Trojan_Win32_Cobaltstrike_SB_MTB{
	meta:
		description = "Trojan:Win32/Cobaltstrike.SB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {88 1c 01 ff 46 90 01 01 8b 86 90 01 04 03 46 90 01 01 35 90 01 04 29 46 90 01 01 8b 86 90 01 04 01 46 90 01 01 8b 46 90 01 01 31 46 90 01 01 b8 90 01 04 2b 86 90 01 04 2b 86 90 01 04 01 46 90 01 01 8b 86 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}