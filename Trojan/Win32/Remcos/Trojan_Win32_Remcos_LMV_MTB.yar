
rule Trojan_Win32_Remcos_LMV_MTB{
	meta:
		description = "Trojan:Win32/Remcos.LMV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {41 83 c4 04 81 eb 9f 9c 00 00 5b 8b 8d ?? ?? ff ff 0f b6 94 0d ?? ?? ff ff 8b 85 ?? ?? ff ff 03 85 ?? ?? ff ff 0f b6 08 33 ca 8b 95 60 f0 ff ff 03 95 d0 fa ff ff 88 0a e9 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}