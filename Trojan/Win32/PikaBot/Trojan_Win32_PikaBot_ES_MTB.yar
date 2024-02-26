
rule Trojan_Win32_PikaBot_ES_MTB{
	meta:
		description = "Trojan:Win32/PikaBot.ES!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {13 db 8d 4d 90 01 01 45 be 90 01 04 32 ed 34 90 01 01 4b d7 32 3e 32 ad 90 01 04 a5 90 00 } //01 00 
		$a_00_1 = {43 72 61 73 68 } //00 00  Crash
	condition:
		any of ($a_*)
 
}