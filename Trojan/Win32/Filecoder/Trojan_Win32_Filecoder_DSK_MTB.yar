
rule Trojan_Win32_Filecoder_DSK_MTB{
	meta:
		description = "Trojan:Win32/Filecoder.DSK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_02_0 = {8a 54 24 15 8a 44 24 17 0a 44 24 13 88 14 3e 83 25 ?? ?? ?? ?? 00 8a 54 24 16 88 54 3e 01 81 3d ?? ?? ?? ?? d8 01 00 00 88 44 24 17 75 } //2
	condition:
		((#a_02_0  & 1)*2) >=2
 
}