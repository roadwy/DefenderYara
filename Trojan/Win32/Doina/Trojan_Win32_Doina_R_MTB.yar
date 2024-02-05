
rule Trojan_Win32_Doina_R_MTB{
	meta:
		description = "Trojan:Win32/Doina.R!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {ac 83 ec 04 c7 04 24 90 01 04 83 c4 04 32 02 aa 42 49 90 00 } //01 00 
		$a_03_1 = {ac 30 d0 aa c1 ca 08 49 83 ec 04 c7 04 24 90 01 04 83 c4 04 85 c9 75 e7 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}