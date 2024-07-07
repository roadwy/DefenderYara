
rule Trojan_Win32_DarkGate_AL_MTB{
	meta:
		description = "Trojan:Win32/DarkGate.AL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {31 42 04 b8 90 01 04 8b 4a 90 01 01 2b 44 24 90 01 01 01 82 90 01 02 00 00 8b 47 90 01 01 0f af ce 89 af 90 01 02 00 00 89 4c 24 90 01 01 8b d1 8b 4f 90 01 01 8b 5c 24 90 01 01 c1 ea 90 00 } //1
		$a_03_1 = {88 14 01 8b cb ff 47 90 01 01 8b 57 90 01 01 8b 47 90 01 01 c1 e9 90 01 01 88 0c 02 ff 47 90 01 01 8b 4f 90 01 01 8b 47 90 01 01 88 1c 01 8b 4c 24 90 01 01 ff 47 90 01 01 83 c1 04 89 4c 24 90 01 01 81 f9 90 01 04 0f 8c 90 01 02 ff ff 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}