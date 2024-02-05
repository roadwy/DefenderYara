
rule Trojan_Win32_Wukill_MA_MTB{
	meta:
		description = "Trojan:Win32/Wukill.MA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 05 00 "
		
	strings :
		$a_01_0 = {49 d3 7e d0 cc 0b 2d 4a 87 dd d0 f2 a8 af fb 51 } //05 00 
		$a_01_1 = {bc 4a 40 00 4c 00 00 00 56 42 35 21 f0 1f 76 62 36 63 68 73 2e 64 6c } //00 00 
	condition:
		any of ($a_*)
 
}