
rule Trojan_Win32_Convagent_BH_MTB{
	meta:
		description = "Trojan:Win32/Convagent.BH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b d0 8d 45 ec 03 c7 0f be 04 78 33 c8 0f be 44 5d ec 33 c8 8b 45 e4 0f be 44 05 ec 33 c8 8b 45 dc 33 d1 8b 4d e8 33 55 e0 31 14 08 83 c1 04 89 4d e8 3b 4d 1c 0f } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}