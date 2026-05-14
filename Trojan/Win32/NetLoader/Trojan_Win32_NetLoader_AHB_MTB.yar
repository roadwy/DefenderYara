
rule Trojan_Win32_NetLoader_AHB_MTB{
	meta:
		description = "Trojan:Win32/NetLoader.AHB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,32 00 32 00 02 00 00 "
		
	strings :
		$a_03_0 = {2b ca d2 e0 8a ca 0f b6 f8 ba ?? ?? ?? ?? 0f b6 c3 d3 e8 8b ce 83 e1 } //30
		$a_01_1 = {44 65 66 65 6e 64 65 72 20 65 78 63 6c 75 73 69 6f 6e 3a 20 55 41 43 20 61 73 6b 65 64 20 66 6f 72 20 25 73 } //20 Defender exclusion: UAC asked for %s
	condition:
		((#a_03_0  & 1)*30+(#a_01_1  & 1)*20) >=50
 
}