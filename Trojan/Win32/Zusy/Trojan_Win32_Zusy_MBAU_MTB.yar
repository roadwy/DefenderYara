
rule Trojan_Win32_Zusy_MBAU_MTB{
	meta:
		description = "Trojan:Win32/Zusy.MBAU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {2e 64 6c 6c 00 4e 69 73 66 64 6a 69 68 73 72 6a 6f 68 41 6f 63 76 62 6f 64 6a 72 00 51 6f 78 63 76 6f 73 67 6a 72 67 68 73 64 72 6f 68 6a 72 41 61 66 66 66 00 58 69 67 64 6f 70 70 64 70 76 6f 6b 6a 72 6f 68 } //00 00 
	condition:
		any of ($a_*)
 
}