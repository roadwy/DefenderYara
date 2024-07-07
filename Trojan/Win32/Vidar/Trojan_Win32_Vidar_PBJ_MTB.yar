
rule Trojan_Win32_Vidar_PBJ_MTB{
	meta:
		description = "Trojan:Win32/Vidar.PBJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {03 d8 81 e3 90 01 04 90 13 8b 94 9d 90 01 04 89 94 bd 90 01 04 89 84 9d 90 01 04 8b 8c bd 90 01 04 03 c1 25 ff 00 00 80 90 13 8b 95 90 01 04 8a 0a 0f b6 d1 39 94 85 90 01 04 8b 95 90 01 04 8d 84 85 90 01 04 90 13 8a 00 32 c1 8b 8d 90 01 04 88 04 11 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}