
rule Trojan_Win32_RedLine_MBEV_MTB{
	meta:
		description = "Trojan:Win32/RedLine.MBEV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {f6 17 80 07 58 fe 07 47 e2 } //01 00 
		$a_01_1 = {71 76 69 6b 72 6a 71 69 6a 78 77 6b 6c 68 76 6b 6c 72 68 61 6b 6c } //00 00 
	condition:
		any of ($a_*)
 
}