
rule Trojan_Win32_Sfone_RD_MTB{
	meta:
		description = "Trojan:Win32/Sfone.RD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {7e 72 92 e7 7a cf 4b 7e 35 cb 3f be 15 e4 78 98 38 c7 b9 fb 49 07 2d 61 80 73 6b b2 c9 5a d5 27 } //00 00 
	condition:
		any of ($a_*)
 
}