
rule Trojan_Win32_Babar_HZN_MTB{
	meta:
		description = "Trojan:Win32/Babar.HZN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {83 c1 01 89 4d fc 8b 55 fc 3b 55 0c 73 ?? 8b 45 f8 c1 e8 08 8b 4d f4 03 4d fc 0f b6 11 33 55 f8 81 e2 ff 00 00 00 33 04 95 ?? ?? ?? ?? 89 45 f8 eb } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}