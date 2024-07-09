
rule Trojan_Win32_Fragtor_KAG_MTB{
	meta:
		description = "Trojan:Win32/Fragtor.KAG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {99 f7 ff 0f b6 81 ?? ?? ?? ?? c0 c8 03 32 82 ?? ?? ?? ?? 88 81 ?? ?? ?? ?? 8d 42 01 99 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}