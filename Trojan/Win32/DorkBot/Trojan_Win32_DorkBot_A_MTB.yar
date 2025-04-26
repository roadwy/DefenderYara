
rule Trojan_Win32_DorkBot_A_MTB{
	meta:
		description = "Trojan:Win32/DorkBot.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {0b ca 88 4d f9 0f b6 45 fe 83 e0 ?? c1 e0 04 0f b6 4d ff 83 e1 ?? c1 f9 02 0b c1 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}