
rule Trojan_Win32_Dapato_BAB_MTB{
	meta:
		description = "Trojan:Win32/Dapato.BAB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {8a 00 34 b9 8b 15 ?? ?? ?? ?? 03 13 73 ?? e8 ?? ?? ?? ?? 88 02 ff 03 81 3b ?? ?? ?? ?? 75 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}