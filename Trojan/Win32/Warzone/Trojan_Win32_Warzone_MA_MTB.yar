
rule Trojan_Win32_Warzone_MA_MTB{
	meta:
		description = "Trojan:Win32/Warzone.MA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {48 8d 4f 2c 48 03 c8 8b 51 f8 4d 2b d6 44 8b 01 48 03 d6 44 8b 49 fc 4c 03 c5 4d 85 c9 74 ?? 41 8a 00 4d 03 c6 88 02 49 03 d6 4d 2b ce 75 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}