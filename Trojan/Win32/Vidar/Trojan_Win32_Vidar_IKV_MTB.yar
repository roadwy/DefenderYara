
rule Trojan_Win32_Vidar_IKV_MTB{
	meta:
		description = "Trojan:Win32/Vidar.IKV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {8d 64 24 00 8d 4c 24 08 c7 44 24 04 ?? ?? ?? ?? c7 44 24 08 ?? ?? ?? ?? e8 ?? ?? ?? ?? 8b 44 24 08 83 c0 46 89 44 24 04 83 6c 24 04 46 8a 4c 24 ?? 30 0c 33 83 ff 0f 75 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}