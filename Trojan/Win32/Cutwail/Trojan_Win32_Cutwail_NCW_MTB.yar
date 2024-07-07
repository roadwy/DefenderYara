
rule Trojan_Win32_Cutwail_NCW_MTB{
	meta:
		description = "Trojan:Win32/Cutwail.NCW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {81 c6 0f fc ff ff 8d 81 90 01 04 81 f7 ea 0d 00 00 89 74 24 90 01 01 81 f5 f9 0b 00 00 3b d8 0f 8f 3b 01 00 00 8b c7 35 90 01 04 3b d8 0f 8d 2c 01 90 00 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}