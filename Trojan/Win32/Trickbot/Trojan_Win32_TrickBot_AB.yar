
rule Trojan_Win32_TrickBot_AB{
	meta:
		description = "Trojan:Win32/TrickBot.AB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {74 61 62 64 6c 6c 5f 78 36 34 2e 64 6c 6c } //00 00 
	condition:
		any of ($a_*)
 
}