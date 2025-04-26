
rule Trojan_Win32_Spynoon_DB_MTB{
	meta:
		description = "Trojan:Win32/Spynoon.DB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 03 00 00 "
		
	strings :
		$a_03_0 = {8a 04 0f f6 d0 32 c1 02 c1 f6 d0 02 c1 f6 d0 02 c1 d0 c8 02 c1 f6 d8 32 c1 f6 d0 2c ?? 88 04 0f 41 3b 4d fc 72 da } //2
		$a_03_1 = {8a 04 0f b2 ?? 04 ?? d0 c0 34 ?? 2a d0 32 d1 2a d1 c0 ca ?? f6 d2 c0 ca ?? 80 f2 ?? 80 ea ?? 80 f2 ?? f6 da c0 c2 ?? 80 c2 ?? 88 14 0f 41 3b 4d fc 72 cd } //2
		$a_01_2 = {47 46 48 46 47 48 54 52 59 52 45 } //5 GFHFGHTRYRE
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*2+(#a_01_2  & 1)*5) >=7
 
}