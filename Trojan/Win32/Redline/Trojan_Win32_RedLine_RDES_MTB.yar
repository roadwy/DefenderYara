
rule Trojan_Win32_RedLine_RDES_MTB{
	meta:
		description = "Trojan:Win32/RedLine.RDES!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_01_0 = {80 f1 73 80 e9 6c 80 f1 74 80 c1 4e 80 f1 70 80 e9 65 80 f1 22 80 e9 73 80 f1 2a 88 88 } //00 00 
	condition:
		any of ($a_*)
 
}