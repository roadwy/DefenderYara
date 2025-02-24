
rule Trojan_Win32_Stealc_AJFA_MTB{
	meta:
		description = "Trojan:Win32/Stealc.AJFA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {33 75 fc 89 75 dc 8b 45 dc 29 45 f8 81 c7 47 86 c8 61 83 6d ?? 01 0f 85 8f } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}