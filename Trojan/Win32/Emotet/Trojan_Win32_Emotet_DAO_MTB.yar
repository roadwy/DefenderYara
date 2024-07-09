
rule Trojan_Win32_Emotet_DAO_MTB{
	meta:
		description = "Trojan:Win32/Emotet.DAO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {83 c7 01 81 e7 ?? ?? ?? ?? 0f b6 44 3c 1c 03 e8 81 e5 90 1b 00 0f b6 5c 2c 1c 6a 00 88 5c 3c 20 6a 00 89 44 24 18 88 44 2c 24 ff 15 ?? ?? ?? ?? 02 5c 24 10 8b 44 24 18 0f b6 cb 8a 54 0c 1c 30 14 30 83 c6 01 3b } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}