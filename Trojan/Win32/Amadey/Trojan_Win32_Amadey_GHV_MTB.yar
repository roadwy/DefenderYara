
rule Trojan_Win32_Amadey_GHV_MTB{
	meta:
		description = "Trojan:Win32/Amadey.GHV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b cf 8d 44 24 ?? e8 ?? ?? ?? ?? 8b 44 24 ?? 31 44 24 ?? 8b 54 24 ?? 8b 44 24 ?? 52 50 8d 4c 24 ?? 51 e8 ?? ?? ?? ?? 8b 44 24 ?? 29 44 24 ?? 81 44 24 ?? 47 86 c8 61 83 eb } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}