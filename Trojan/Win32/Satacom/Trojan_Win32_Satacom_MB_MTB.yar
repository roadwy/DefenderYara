
rule Trojan_Win32_Satacom_MB_MTB{
	meta:
		description = "Trojan:Win32/Satacom.MB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_01_0 = {0f be 44 15 f4 c1 f8 04 8d 0c 88 8b 55 ec 03 55 f8 88 0a 8b 45 f8 83 c0 01 89 45 f8 b9 01 00 00 00 d1 e1 0f be 54 0d f4 83 fa 40 0f 84 a0 00 00 00 } //00 00 
	condition:
		any of ($a_*)
 
}