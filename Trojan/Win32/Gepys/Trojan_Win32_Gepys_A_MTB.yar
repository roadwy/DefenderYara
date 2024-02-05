
rule Trojan_Win32_Gepys_A_MTB{
	meta:
		description = "Trojan:Win32/Gepys.A!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {0f b6 04 33 33 47 60 88 04 33 46 3b 75 0c 7c f0 } //00 00 
	condition:
		any of ($a_*)
 
}