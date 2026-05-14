
rule Trojan_Win32_Fareit_BAH_MTB{
	meta:
		description = "Trojan:Win32/Fareit.BAH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {8a 00 34 26 8b 15 ?? ?? ?? ?? 03 d3 73 ?? e8 ?? ?? ?? ?? 88 02 90 90 43 81 fb bd 59 00 00 75 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}