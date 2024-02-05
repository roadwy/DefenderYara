
rule Trojan_Win32_Ditertag_RT_MTB{
	meta:
		description = "Trojan:Win32/Ditertag.RT!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {89 db 81 c3 15 2f cc 6a 81 c3 78 4d a2 2c 31 0f 09 f6 81 c7 02 00 00 00 4e 81 eb 01 00 00 00 39 c7 7c 9f } //00 00 
	condition:
		any of ($a_*)
 
}