
rule Trojan_Win32_Emotet_DAF_MTB{
	meta:
		description = "Trojan:Win32/Emotet.DAF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {6a 00 6a 00 0f b6 94 3d ?? ?? ?? ?? 8d 84 3d 90 1b 00 03 ca 23 ce 89 55 10 89 4d f0 0f b6 9c 0d 90 1b 00 8d 8c 0d 90 1b 00 88 18 88 11 ff 15 ?? ?? ?? ?? 02 5d 10 8b 45 08 8b 4d fc 0f b6 d3 03 c1 8a 94 15 90 1b 00 30 10 41 3b 4d 0c 89 4d fc 7c a4 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}