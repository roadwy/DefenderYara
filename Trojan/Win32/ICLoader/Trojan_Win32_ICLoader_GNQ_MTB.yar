
rule Trojan_Win32_ICLoader_GNQ_MTB{
	meta:
		description = "Trojan:Win32/ICLoader.GNQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {40 00 00 40 2e 64 61 ?? ?? 00 00 00 98 ?? ?? ?? ?? f0 49 00 00 32 00 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}