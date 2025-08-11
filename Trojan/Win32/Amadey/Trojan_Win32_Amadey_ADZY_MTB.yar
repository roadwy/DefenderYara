
rule Trojan_Win32_Amadey_ADZY_MTB{
	meta:
		description = "Trojan:Win32/Amadey.ADZY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {56 a3 54 74 46 00 ff 15 ?? ?? ?? ?? 68 f8 23 45 00 56 a3 58 74 46 00 ff 15 ?? ?? ?? ?? 68 0c 24 45 00 56 a3 5c 74 46 00 ff 15 ?? ?? ?? ?? 68 1c 24 45 00 56 a3 60 74 46 00 ff 15 ?? ?? ?? ?? 68 30 24 45 00 56 a3 64 74 46 00 ff 15 ?? ?? ?? ?? 68 44 24 45 00 56 a3 68 74 46 00 ff 15 ?? ?? ?? ?? 68 5c 24 45 00 56 a3 6c 74 46 00 ff 15 ?? ?? ?? ?? 68 70 24 45 00 56 a3 70 74 46 00 ff 15 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}