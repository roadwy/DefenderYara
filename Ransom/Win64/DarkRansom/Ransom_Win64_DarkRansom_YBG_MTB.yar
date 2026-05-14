
rule Ransom_Win64_DarkRansom_YBG_MTB{
	meta:
		description = "Ransom:Win64/DarkRansom.YBG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 03 00 00 "
		
	strings :
		$a_03_0 = {0f af d8 89 d9 89 c8 48 69 c0 ?? ?? ?? ?? 48 c1 e8 20 89 ca 29 c2 d1 ea 01 d0 c1 e8 05 89 c2 89 d0 c1 e0 06 29 d0 29 c1 89 ca 89 d1 48 8b 55 20 48 8b 45 f8 48 01 c2 0f b6 44 0d b0 88 02 } //10
		$a_01_1 = {48 8b 85 08 11 00 00 48 01 d0 0f b6 00 89 ca 31 c2 8b 85 ec 10 00 00 88 54 05 c0 } //1
		$a_01_2 = {ba 00 00 00 00 48 f7 75 20 48 8b 45 18 48 01 d0 0f b6 00 31 c8 88 45 e7 } //1
	condition:
		((#a_03_0  & 1)*10+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=11
 
}