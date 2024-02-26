
rule Trojan_Win32_Shifu_GAB_MTB{
	meta:
		description = "Trojan:Win32/Shifu.GAB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 0a 00 "
		
	strings :
		$a_01_0 = {b6 63 32 ca 00 01 00 c8 0a d3 8b 16 } //0a 00 
		$a_03_1 = {32 00 02 04 00 cc cc 4f 66 23 19 4e 6c 47 58 00 a4 a4 90 01 04 06 84 18 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}