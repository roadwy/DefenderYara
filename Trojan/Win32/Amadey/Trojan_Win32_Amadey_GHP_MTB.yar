
rule Trojan_Win32_Amadey_GHP_MTB{
	meta:
		description = "Trojan:Win32/Amadey.GHP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {6a 00 6a 00 ff 15 ?? ?? ?? ?? 8b 44 24 ?? 81 44 24 ?? 47 86 c8 61 33 c6 2b d8 83 6c 24 ?? ?? 89 44 24 ?? 89 5c 24 ?? 0f 85 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}