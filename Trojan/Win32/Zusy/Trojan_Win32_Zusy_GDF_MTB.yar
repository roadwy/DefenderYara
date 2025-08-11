
rule Trojan_Win32_Zusy_GDF_MTB{
	meta:
		description = "Trojan:Win32/Zusy.GDF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b 45 f0 01 d0 0f b6 00 01 c8 0f b6 c0 0f b6 8c 05 ?? ?? ?? ?? 8b 55 08 8b 45 ec 01 d0 31 cb 89 da 88 10 83 45 ec 01 8b 45 ec 3b 45 0c 0f 82 } //10
		$a_03_1 = {89 e5 83 ec 14 8b 45 10 88 45 ec c7 45 fc 00 00 00 00 ?? ?? 8b 55 08 8b 45 fc 01 d0 0f b6 00 8b 4d 08 8b 55 fc 01 ca 32 45 ec 88 02 83 45 fc 01 8b 45 fc 3b 45 0c } //10
	condition:
		((#a_03_0  & 1)*10+(#a_03_1  & 1)*10) >=10
 
}