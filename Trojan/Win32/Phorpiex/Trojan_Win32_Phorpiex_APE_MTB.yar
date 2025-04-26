
rule Trojan_Win32_Phorpiex_APE_MTB{
	meta:
		description = "Trojan:Win32/Phorpiex.APE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 03 00 00 "
		
	strings :
		$a_03_0 = {8b 4d 08 03 4d fc 0f be 11 33 d0 8b 45 08 03 45 fc 88 10 eb ?? 8b 4d 08 03 4d fc 0f be 11 f7 d2 8b 45 08 03 45 fc 88 10 } //5
		$a_01_1 = {31 00 38 00 35 00 2e 00 32 00 31 00 35 00 2e 00 31 00 31 00 33 00 2e 00 36 00 36 00 } //3 185.215.113.66
		$a_03_2 = {83 ec 18 a1 ?? 20 40 00 89 45 ec 8b 0d ?? 20 40 00 89 4d f0 8b 15 ?? 20 40 00 89 55 f4 a1 ?? 20 40 00 89 45 f8 c7 45 ?? ?? ?? ?? ?? eb 09 8b 4d fc 83 c1 01 89 4d fc 8b 55 08 52 } //2
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*3+(#a_03_2  & 1)*2) >=10
 
}