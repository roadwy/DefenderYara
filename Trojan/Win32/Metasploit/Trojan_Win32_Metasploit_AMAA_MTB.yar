
rule Trojan_Win32_Metasploit_AMAA_MTB{
	meta:
		description = "Trojan:Win32/Metasploit.AMAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {83 eb fc 31 43 10 03 43 10 e2 } //00 00 
	condition:
		any of ($a_*)
 
}