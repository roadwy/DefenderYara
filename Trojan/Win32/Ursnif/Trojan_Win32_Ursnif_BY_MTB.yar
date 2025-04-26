
rule Trojan_Win32_Ursnif_BY_MTB{
	meta:
		description = "Trojan:Win32/Ursnif.BY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 54 24 34 8b f5 8b 81 c4 00 00 00 81 f6 ?? ?? ?? ?? 8b 6c 24 20 8b 7c 24 18 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}