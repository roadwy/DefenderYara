
rule Trojan_Win32_Razy_V_MTB{
	meta:
		description = "Trojan:Win32/Razy.V!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 03 00 00 "
		
	strings :
		$a_02_0 = {8d 4a 03 32 8a ?? ?? ?? ?? 32 cb 88 8a ?? ?? ?? ?? 42 83 fa ?? 7c e9 } //1
		$a_02_1 = {8d 41 03 32 81 ?? ?? ?? ?? 32 c2 88 81 ?? ?? ?? ?? 41 83 f9 ?? 7c e9 } //1
		$a_02_2 = {8d 41 03 32 c2 30 81 ?? ?? ?? ?? 41 83 f9 ?? 7c ef } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1+(#a_02_2  & 1)*1) >=1
 
}