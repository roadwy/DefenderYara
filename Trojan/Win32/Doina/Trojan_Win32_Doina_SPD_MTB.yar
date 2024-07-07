
rule Trojan_Win32_Doina_SPD_MTB{
	meta:
		description = "Trojan:Win32/Doina.SPD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 "
		
	strings :
		$a_03_0 = {80 f1 56 88 88 90 01 04 8a 88 90 01 04 84 c9 74 0e 90 00 } //4
	condition:
		((#a_03_0  & 1)*4) >=4
 
}