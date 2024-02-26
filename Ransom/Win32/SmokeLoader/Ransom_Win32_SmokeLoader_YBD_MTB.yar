
rule Ransom_Win32_SmokeLoader_YBD_MTB{
	meta:
		description = "Ransom:Win32/SmokeLoader.YBD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {0f b6 55 ef a1 90 01 04 03 45 e4 0f be 08 33 ca 8b 15 a0 dd 45 00 03 55 e4 88 0a 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}