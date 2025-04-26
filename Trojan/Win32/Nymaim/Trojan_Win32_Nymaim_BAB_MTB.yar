
rule Trojan_Win32_Nymaim_BAB_MTB{
	meta:
		description = "Trojan:Win32/Nymaim.BAB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 01 00 00 "
		
	strings :
		$a_03_0 = {8f 45 e4 8b c8 50 8f 45 e8 8a 4d e3 0a 4d ed 80 e1 00 0b c1 8d 00 32 05 ?? ?? ?? ?? 88 45 ef } //3
	condition:
		((#a_03_0  & 1)*3) >=3
 
}