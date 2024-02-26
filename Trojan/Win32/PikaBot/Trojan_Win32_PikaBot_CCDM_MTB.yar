
rule Trojan_Win32_PikaBot_CCDM_MTB{
	meta:
		description = "Trojan:Win32/PikaBot.CCDM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {fc 32 c3 fc } //01 00 
		$a_01_1 = {02 c3 32 c3 c0 c8 c0 fc e9 } //01 00 
		$a_01_2 = {8a db aa fc 49 fc } //01 00 
		$a_01_3 = {45 78 63 70 74 } //00 00  Excpt
	condition:
		any of ($a_*)
 
}