
rule Trojan_Win32_Redline_NEAN_MTB{
	meta:
		description = "Trojan:Win32/Redline.NEAN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 02 00 00 0a 00 "
		
	strings :
		$a_01_0 = {88 55 b3 0f b6 45 b3 33 45 b4 88 45 b3 0f b6 4d b3 03 4d b4 88 4d b3 8b 55 b4 8a 45 b3 88 44 15 dc } //02 00 
		$a_01_1 = {49 00 6e 00 64 00 65 00 63 00 69 00 73 00 69 00 76 00 65 00 20 00 6c 00 65 00 61 00 6b 00 69 00 6e 00 67 00 } //00 00  Indecisive leaking
	condition:
		any of ($a_*)
 
}