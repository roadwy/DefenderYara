
rule Trojan_Win32_Zusy_MBAT_MTB{
	meta:
		description = "Trojan:Win32/Zusy.MBAT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {66 6f 72 6b 32 2e 64 6c 6c 00 50 61 73 64 6f 67 6a 73 65 6f 68 65 6a 68 00 55 59 61 69 73 64 67 69 6a 41 68 73 68 64 68 00 6a 6f 65 67 6f 41 6a 6f 61 6a 67 69 65 6a 68 } //00 00 
	condition:
		any of ($a_*)
 
}