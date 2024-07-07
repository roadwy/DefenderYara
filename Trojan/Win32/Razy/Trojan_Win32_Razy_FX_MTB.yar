
rule Trojan_Win32_Razy_FX_MTB{
	meta:
		description = "Trojan:Win32/Razy.FX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_02_0 = {31 19 81 ea 90 01 04 81 e8 01 00 00 00 81 c1 04 00 00 00 29 f6 39 f9 75 e1 90 00 } //10
	condition:
		((#a_02_0  & 1)*10) >=10
 
}