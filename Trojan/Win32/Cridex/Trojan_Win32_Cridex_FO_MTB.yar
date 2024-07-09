
rule Trojan_Win32_Cridex_FO_MTB{
	meta:
		description = "Trojan:Win32/Cridex.FO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {8b 7c 24 14 81 c1 ?? ?? ?? ?? 89 4c 24 10 89 0d ?? ?? ?? ?? 89 0f b9 ?? ?? ?? ?? 2b c8 0f af ca 81 c1 ?? ?? ?? ?? 03 ce 83 7c 24 18 ?? 75 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}