
rule Trojan_Win32_ICLoader_PVS_MTB{
	meta:
		description = "Trojan:Win32/ICLoader.PVS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_02_0 = {8b 7d 0c 03 7d 08 ?? ?? ?? ?? a1 ?? ?? ?? ?? 03 f8 66 33 c0 8a 65 ff 80 c9 ?? 0c ?? 30 27 61 ff 45 08 e9 } //2
	condition:
		((#a_02_0  & 1)*2) >=2
 
}