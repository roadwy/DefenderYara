
rule Trojan_Win32_Fauppod_GNQ_MTB{
	meta:
		description = "Trojan:Win32/Fauppod.GNQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {46 8a 46 ff 68 ?? ?? ?? ?? 83 c4 04 32 02 47 88 47 ff 89 c0 42 83 ec 04 c7 04 24 ?? ?? ?? ?? 83 c4 04 89 c0 83 e9 01 89 c0 ?? 85 c9 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}