
rule Backdoor_Win32_Androm_CCHT_MTB{
	meta:
		description = "Backdoor:Win32/Androm.CCHT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {b9 9b 00 00 00 be 90 01 04 f3 a5 8b 35 28 30 40 00 c7 83 8c da 04 00 01 00 00 00 ff d6 6a 0a ff d6 6a 0a ff d6 6a 0a ff d6 6a 0a ff d6 8b cb e8 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}