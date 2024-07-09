
rule Trojan_Win32_Lokibot_SIB_MTB{
	meta:
		description = "Trojan:Win32/Lokibot.SIB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {41 00 76 00 6f 00 74 00 61 00 78 00 20 00 42 00 75 00 69 00 6c 00 64 00 65 00 72 00 } //1 Avotax Builder
		$a_03_1 = {5f 66 0f 66 c9 [0-80] b8 ?? ?? ?? ?? [0-b5] 35 ?? ?? ?? ?? 90 08 a0 02 05 ?? ?? ?? ?? 90 08 aa 01 81 34 07 ?? ?? ?? ?? [0-a5] 83 c0 04 [0-a5] 3d ?? ?? ?? ?? [0-0a] 90 18 0f 85 ?? ?? ?? ?? [0-05] 90 18 83 f0 00 [0-5a] ff d7 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}