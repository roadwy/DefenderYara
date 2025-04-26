
rule Trojan_Win32_Offloader_KAG_MTB{
	meta:
		description = "Trojan:Win32/Offloader.KAG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_80_0 = {2f 73 6e 61 6b 65 73 62 61 69 74 2e 69 63 75 } ///snakesbait.icu  5
		$a_80_1 = {2f 73 69 6c 65 6e 74 } ///silent  1
	condition:
		((#a_80_0  & 1)*5+(#a_80_1  & 1)*1) >=6
 
}