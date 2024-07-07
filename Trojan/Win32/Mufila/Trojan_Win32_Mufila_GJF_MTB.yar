
rule Trojan_Win32_Mufila_GJF_MTB{
	meta:
		description = "Trojan:Win32/Mufila.GJF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 14 81 89 55 c8 8b 45 e0 03 45 c8 0f b6 c8 89 4d e0 8b 45 e0 8b 4d d4 8b 14 81 89 55 bc 8b 45 ec 8b 4d d4 8b 55 bc 89 14 81 8b 45 e0 8b 4d d4 8b 55 c8 89 14 81 8b 45 c8 03 45 bc 0f b6 c8 8b 55 0c 03 55 f8 0f b6 02 8b 55 d4 33 04 8a 8b 4d 0c 03 4d f8 88 01 } //10
	condition:
		((#a_01_0  & 1)*10) >=10
 
}