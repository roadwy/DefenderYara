
rule Trojan_Win32_Matanbuchus_MKZ_MTB{
	meta:
		description = "Trojan:Win32/Matanbuchus.MKZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f b6 c0 99 83 f0 5f b9 01 00 00 00 6b d1 00 88 84 15 28 f8 ff ff 6a 3e e8 ?? ?? ?? ?? 83 c4 04 0f b6 c0 99 83 f0 5f b9 01 00 00 00 c1 e1 00 88 84 0d 28 f8 ff ff 6a 73 e8 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}