
rule Trojan_Win32_Emotet_DDP_MTB{
	meta:
		description = "Trojan:Win32/Emotet.DDP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_02_0 = {6a 00 ff 55 ?? 56 6a 00 89 45 ?? ff 55 ?? 8b 55 ?? 52 89 45 ?? ff 55 ?? 8b 4d ?? 6a 00 89 45 ?? 8b 85 ?? ?? ?? ?? 50 68 00 30 00 00 51 6a 00 ff d3 50 ff d7 } //1
		$a_00_1 = {bf 00 30 00 00 50 57 ff 75 d8 53 ff 55 bc 50 ff 55 b8 ff 75 d8 89 45 dc ff 75 c4 50 e8 80 53 00 00 83 c4 0c } //1
	condition:
		((#a_02_0  & 1)*1+(#a_00_1  & 1)*1) >=1
 
}