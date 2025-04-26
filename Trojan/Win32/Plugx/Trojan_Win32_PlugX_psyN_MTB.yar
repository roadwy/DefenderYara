
rule Trojan_Win32_PlugX_psyN_MTB{
	meta:
		description = "Trojan:Win32/PlugX.psyN!MTB,SIGNATURE_TYPE_PEHSTR,07 00 07 00 01 00 00 "
		
	strings :
		$a_01_0 = {83 ed 02 9c ff 34 24 68 6b 30 df 90 e8 fe 04 00 00 80 fe bd 66 0f a3 f8 e9 e3 ff ff ff } //7
	condition:
		((#a_01_0  & 1)*7) >=7
 
}