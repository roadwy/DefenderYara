
rule Trojan_Win32_Emotet_DCB_MTB{
	meta:
		description = "Trojan:Win32/Emotet.DCB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_02_0 = {8b c8 8b c6 33 d2 f7 f1 33 c0 33 c9 8a 0c 3e 66 8b 04 53 50 51 e8 ?? ?? ?? ?? 83 c4 0c 88 04 3e 46 3b f5 75 } //5
		$a_02_1 = {0f b6 44 34 34 0f b6 cb 03 c1 99 b9 ?? ?? ?? ?? f7 f9 83 c4 ?? 83 c5 01 0f b6 54 14 ?? 30 55 ff 83 bc 24 ?? ?? ?? ?? 00 0f 85 } //5
	condition:
		((#a_02_0  & 1)*5+(#a_02_1  & 1)*5) >=5
 
}