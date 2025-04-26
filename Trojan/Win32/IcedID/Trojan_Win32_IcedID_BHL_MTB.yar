
rule Trojan_Win32_IcedID_BHL_MTB{
	meta:
		description = "Trojan:Win32/IcedID.BHL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {83 c6 04 88 45 dc 0f b6 4c 9d da 0f b6 89 ?? ?? ?? ?? 30 4d dd 0f b6 4c 9d db 0f b6 89 60 a6 02 01 30 4d de 0f b6 4c 9d d8 32 46 fc 0f b6 89 ?? ?? ?? ?? 30 4d df 88 45 dc 89 75 cc b8 01 00 00 00 83 fb 08 74 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}