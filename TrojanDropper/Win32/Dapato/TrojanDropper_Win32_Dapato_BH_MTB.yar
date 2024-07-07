
rule TrojanDropper_Win32_Dapato_BH_MTB{
	meta:
		description = "TrojanDropper:Win32/Dapato.BH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {01 c1 8b 45 f8 8b 55 08 01 c2 8b 45 f8 89 4d f4 b9 20 00 00 00 89 55 f0 99 f7 f9 b8 00 20 40 00 01 d0 8b 4d f0 0f be 09 0f be 10 31 d1 8b 45 f4 88 08 eb } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}