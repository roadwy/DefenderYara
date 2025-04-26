
rule Trojan_Win32_Neoreblamy_CD_MTB{
	meta:
		description = "Trojan:Win32/Neoreblamy.CD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {f7 f1 0f af 45 f8 89 45 f4 69 4d f4 ?? 00 00 00 69 45 f4 ?? 00 00 00 2b c8 03 4d ?? ff 34 8f ff 34 b3 e8 ?? ?? ff ff 89 04 b3 46 8b 45 fc 03 45 ?? 59 59 3b f0 72 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}