
rule Trojan_Win32_Mokes_MAK_MTB{
	meta:
		description = "Trojan:Win32/Mokes.MAK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {d3 e0 89 45 f8 8b 45 d0 01 45 f8 8b 4d d8 8b c3 c1 e8 90 02 01 89 45 f4 8d 45 f4 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}