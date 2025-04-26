
rule Trojan_Win32_Vebzenpak_GV_MTB{
	meta:
		description = "Trojan:Win32/Vebzenpak.GV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {8b 1c 0a 50 [0-20] 81 f3 [0-30] f7 d7 [0-20] 89 1c 08 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}