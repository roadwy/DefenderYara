
rule Trojan_Win32_Qakbot_PO_MTB{
	meta:
		description = "Trojan:Win32/Qakbot.PO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b d3 89 46 90 01 01 8b 86 90 01 04 33 06 01 46 90 01 01 8b 4e 90 01 01 33 0e 81 e9 90 02 04 c1 ea 08 09 4e 90 01 01 8b 46 90 01 01 8b 4e 90 01 01 88 14 01 8b 86 90 01 04 ff 46 90 01 01 05 90 01 04 03 46 90 01 01 09 46 90 01 01 8b 56 90 01 01 8b 46 90 01 01 88 1c 02 ff 46 90 01 01 8b 46 90 01 01 2b 86 90 02 04 05 90 02 04 31 86 90 02 04 81 ff 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}