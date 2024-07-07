
rule Trojan_Win32_Emotet_RBA_MTB{
	meta:
		description = "Trojan:Win32/Emotet.RBA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {8b 0b 8d 5b 04 33 90 01 02 0f 90 01 02 66 90 01 02 8b 90 01 01 c1 90 01 02 8d 90 01 02 0f 90 01 02 66 90 01 03 c1 90 01 02 0f 90 01 02 c1 90 01 02 47 66 90 01 03 0f 90 01 02 66 90 01 03 3b 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}