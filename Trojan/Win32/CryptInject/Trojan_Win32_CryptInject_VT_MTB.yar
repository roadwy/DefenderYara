
rule Trojan_Win32_CryptInject_VT_MTB{
	meta:
		description = "Trojan:Win32/CryptInject.VT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {03 75 f8 80 36 f9 90 90 90 90 ff 45 fc 81 7d fc 1a 5a 00 00 75 e7 90 00 } //01 00 
		$a_01_1 = {74 7c 59 04 06 06 a9 06 ae a9 aa 06 6e 55 f9 f9 } //00 00 
	condition:
		any of ($a_*)
 
}