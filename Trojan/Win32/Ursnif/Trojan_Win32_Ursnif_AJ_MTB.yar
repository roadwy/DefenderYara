
rule Trojan_Win32_Ursnif_AJ_MTB{
	meta:
		description = "Trojan:Win32/Ursnif.AJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {8b 44 24 0c 30 0c 30 b8 01 00 00 00 83 f0 04 83 6c 24 0c 01 83 7c 24 0c 00 0f 8d ?? ?? ff ff } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}