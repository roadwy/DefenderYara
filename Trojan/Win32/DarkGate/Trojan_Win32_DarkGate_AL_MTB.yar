
rule Trojan_Win32_DarkGate_AL_MTB{
	meta:
		description = "Trojan:Win32/DarkGate.AL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {31 42 04 b8 ?? ?? ?? ?? 8b 4a ?? 2b 44 24 ?? 01 82 ?? ?? 00 00 8b 47 ?? 0f af ce 89 af ?? ?? 00 00 89 4c 24 ?? 8b d1 8b 4f ?? 8b 5c 24 ?? c1 ea } //1
		$a_03_1 = {88 14 01 8b cb ff 47 ?? 8b 57 ?? 8b 47 ?? c1 e9 ?? 88 0c 02 ff 47 ?? 8b 4f ?? 8b 47 ?? 88 1c 01 8b 4c 24 ?? ff 47 ?? 83 c1 04 89 4c 24 ?? 81 f9 ?? ?? ?? ?? 0f 8c ?? ?? ff ff } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}