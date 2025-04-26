
rule Trojan_Win32_Nymaim_BAD_MTB{
	meta:
		description = "Trojan:Win32/Nymaim.BAD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 01 00 00 "
		
	strings :
		$a_01_0 = {21 c6 56 ff 32 58 f8 83 d2 04 f8 83 d0 d4 c1 c8 08 29 d8 48 89 c3 c1 c3 08 89 06 } //3
	condition:
		((#a_01_0  & 1)*3) >=3
 
}