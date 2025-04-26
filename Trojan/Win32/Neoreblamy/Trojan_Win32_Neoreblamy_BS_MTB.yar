
rule Trojan_Win32_Neoreblamy_BS_MTB{
	meta:
		description = "Trojan:Win32/Neoreblamy.BS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {33 d2 c7 45 fc ?? 00 00 00 8b 4d fc 8b 45 f8 f7 f1 0f af 45 fc 8b 4d f8 2b c8 ff 34 8f ff 34 b3 e8 ?? ?? ff ff 89 04 b3 46 8b 45 f4 03 45 f0 59 59 3b f0 72 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}