
rule Trojan_Win32_Strab_CD_MTB{
	meta:
		description = "Trojan:Win32/Strab.CD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 02 00 "
		
	strings :
		$a_03_0 = {01 45 fc 8b 45 fc 8a 04 30 8b 0d 90 02 04 88 04 0e 90 00 } //02 00 
		$a_01_1 = {81 f9 4a 79 02 0f 7f 0d 41 81 f9 b2 97 76 67 0f 8c } //00 00 
	condition:
		any of ($a_*)
 
}