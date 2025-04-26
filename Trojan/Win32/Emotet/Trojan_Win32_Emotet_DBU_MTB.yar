
rule Trojan_Win32_Emotet_DBU_MTB{
	meta:
		description = "Trojan:Win32/Emotet.DBU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {8b 0c b0 03 cb e8 ?? ?? ?? ?? 35 ?? ?? ?? ?? 3b 45 fc 74 12 8b 45 f8 46 3b 77 18 72 e3 } //1
		$a_02_1 = {d3 e7 83 f8 ?? 72 ?? 83 f8 ?? 77 ?? 83 c0 ?? 89 45 f8 83 c6 ?? 01 55 f8 01 7d f8 29 5d f8 66 83 3e 00 0f 85 ?? ?? ?? ?? 8b 5d f4 8b 7d f0 8b 45 f8 35 ?? ?? ?? ?? 3b 45 ec 74 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}