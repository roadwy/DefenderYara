
rule Trojan_Win32_Ursnif_GB_MTB{
	meta:
		description = "Trojan:Win32/Ursnif.GB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {30 04 37 4e c7 44 24 [0-30] 81 e3 ?? ?? ?? ?? 81 6c 24 [0-30] 81 44 24 [0-30] 81 6c 24 [0-30] c1 e0 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}