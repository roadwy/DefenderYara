
rule Trojan_Win32_Inject_ZG_bit{
	meta:
		description = "Trojan:Win32/Inject.ZG!bit,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {8a 1c 01 8a 92 ?? ?? ?? ?? 32 da 88 1c 01 } //1
		$a_03_1 = {8a 18 8a 4c ?? ?? 02 d9 88 18 } //1
		$a_03_2 = {8a 18 8b 74 ?? ?? 8a 8a ?? ?? ?? ?? 32 d9 46 85 d2 88 18 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}