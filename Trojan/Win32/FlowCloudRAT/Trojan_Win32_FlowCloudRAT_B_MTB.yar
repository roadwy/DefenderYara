
rule Trojan_Win32_FlowCloudRAT_B_MTB{
	meta:
		description = "Trojan:Win32/FlowCloudRAT.B!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b f8 6a 02 6a 00 57 ff d6 57 ff 15 ?? ?? ?? ?? 6a 00 8b d8 6a ?? 57 89 5d fc ff d6 53 ff 15 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}