
rule Trojan_Win32_ICLoader_BQ_MTB{
	meta:
		description = "Trojan:Win32/ICLoader.BQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b c8 83 c9 02 2b d1 33 c9 8a 0d ?? ?? ?? 00 89 15 ?? ?? ?? 00 8b 15 ?? ?? ?? 00 83 ca 01 0f af d1 33 c2 a3 } //3
		$a_03_1 = {55 8b ec 83 ec 0c 53 56 57 e8 ?? ?? ?? ff 89 45 fc e9 } //2
	condition:
		((#a_03_0  & 1)*3+(#a_03_1  & 1)*2) >=5
 
}