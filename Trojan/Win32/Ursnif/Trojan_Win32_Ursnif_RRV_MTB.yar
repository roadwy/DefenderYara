
rule Trojan_Win32_Ursnif_RRV_MTB{
	meta:
		description = "Trojan:Win32/Ursnif.RRV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {8b 01 8d 14 2e 05 ?? ?? ?? ?? 89 01 66 89 15 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? c1 e1 03 0f b7 f1 0f b6 cb 66 03 ce 66 83 e9 26 66 03 d1 83 c7 04 66 89 15 ?? ?? ?? ?? 81 ff b9 03 00 00 0f 82 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}