
rule Ransom_Win32_Magniber_MB_MTB{
	meta:
		description = "Ransom:Win32/Magniber.MB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_03_0 = {8b 28 33 ff 03 ea 83 c0 90 01 01 89 44 24 90 01 01 c1 cf 90 01 01 0f be 45 00 03 f8 45 80 7d ff 90 01 01 75 f0 8d 04 37 3b 44 24 90 01 01 74 20 8b 44 24 90 01 01 43 3b 5c 24 90 01 01 72 cf 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}