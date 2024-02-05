
rule Trojan_Win32_Copak_DK_MTB{
	meta:
		description = "Trojan:Win32/Copak.DK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 02 00 "
		
	strings :
		$a_01_0 = {31 1a 21 c9 81 e9 01 00 00 00 81 c2 02 00 00 00 29 c0 29 c8 09 c0 39 fa 7c } //02 00 
		$a_01_1 = {83 c4 04 21 fe 4f 43 81 ee 01 00 00 00 68 5a bc 21 87 5e 01 ff 81 fb a7 33 00 01 75 b5 } //00 00 
	condition:
		any of ($a_*)
 
}