
rule Trojan_Win32_Cridex_BS_MTB{
	meta:
		description = "Trojan:Win32/Cridex.BS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {68 50 11 00 00 ff 15 ?? ?? ?? ?? 03 f0 68 50 11 00 00 ff 15 ?? ?? ?? ?? 03 f0 68 50 11 00 00 ff 15 ?? ?? ?? ?? 03 f0 8b 55 ?? 03 55 ?? 8b 45 ?? 8b 4d ?? 8a 0c 31 88 0c 10 8b 55 ?? 83 c2 01 89 55 ?? eb } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}