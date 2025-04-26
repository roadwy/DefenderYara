
rule Trojan_Win32_Cutwail_NCW_MTB{
	meta:
		description = "Trojan:Win32/Cutwail.NCW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {81 c6 0f fc ff ff 8d 81 ?? ?? ?? ?? 81 f7 ea 0d 00 00 89 74 24 ?? 81 f5 f9 0b 00 00 3b d8 0f 8f 3b 01 00 00 8b c7 35 ?? ?? ?? ?? 3b d8 0f 8d 2c 01 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}