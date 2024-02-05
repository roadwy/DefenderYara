
rule Trojan_Win32_RedLine_RDAT_MTB{
	meta:
		description = "Trojan:Win32/RedLine.RDAT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_01_0 = {8b 45 fc 99 be 36 00 00 00 f7 fe 8b 45 08 0f be 14 10 6b d2 25 81 e2 86 03 00 00 33 ca 88 4d fb } //00 00 
	condition:
		any of ($a_*)
 
}