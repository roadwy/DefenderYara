
rule Trojan_Win32_Risepro_RPX_MTB{
	meta:
		description = "Trojan:Win32/Risepro.RPX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {c1 fa 3b 66 ff c2 80 ea 1d f6 d0 c1 f2 99 66 c1 f2 af f6 d1 22 c1 c1 c2 30 e8 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}