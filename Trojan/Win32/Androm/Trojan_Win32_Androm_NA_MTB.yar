
rule Trojan_Win32_Androm_NA_MTB{
	meta:
		description = "Trojan:Win32/Androm.NA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {72 6d 31 b4 3a 55 00 28 ea 45 00 5e 00 05 90 01 04 31 00 00 8b c0 55 8b ec 81 c4 90 01 04 53 89 45 94 90 00 } //5
		$a_01_1 = {69 6e 71 75 69 72 65 5f 76 31 58 70 54 } //1 inquire_v1XpT
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}