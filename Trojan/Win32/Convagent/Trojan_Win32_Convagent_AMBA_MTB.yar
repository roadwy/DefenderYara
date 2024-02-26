
rule Trojan_Win32_Convagent_AMBA_MTB{
	meta:
		description = "Trojan:Win32/Convagent.AMBA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_03_0 = {8d 04 13 d3 ea 89 45 ec c7 05 90 01 04 ee 3d ea f4 03 55 e0 8b 45 ec 31 45 fc 33 55 fc 81 3d 90 01 04 13 02 00 00 89 55 ec 75 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}