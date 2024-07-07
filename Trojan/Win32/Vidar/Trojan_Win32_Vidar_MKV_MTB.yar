
rule Trojan_Win32_Vidar_MKV_MTB{
	meta:
		description = "Trojan:Win32/Vidar.MKV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {01 c8 88 45 90 01 01 0f b6 45 90 01 01 0f b6 84 05 90 01 04 88 45 90 01 01 8b 55 90 01 01 8b 45 90 01 01 01 d0 0f b6 00 32 45 90 01 01 88 45 90 01 01 8b 55 90 01 01 8b 45 90 01 01 01 c2 0f b6 45 90 01 01 88 02 83 45 90 01 02 8b 45 90 01 01 3b 45 90 01 01 0f 8c 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}