
rule Ransom_Win32_GanWaste_A_MTB{
	meta:
		description = "Ransom:Win32/GanWaste.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {8b 16 8b c2 23 c1 8b fa 0b f9 f7 d0 23 c7 8b c8 23 4d 0c 0b 45 0c f7 d1 23 c8 8b 45 fc 83 45 fc 04 89 08 8a cb d3 ca 83 c6 04 4b 8b ca 75 d1 } //1
		$a_03_1 = {8a 16 32 d0 4f 88 11 74 ?? 8b d0 c1 ea 08 32 56 01 88 51 01 4f 74 ?? c1 e8 10 32 46 02 88 41 02 5f c3 } //1
		$a_03_2 = {8a 1f 4d 8a d3 47 e8 ?? ?? ?? ?? 0f b6 c8 0f b6 d3 83 e1 0f c1 ea 04 33 ca c1 e8 04 33 04 8e 85 ed 75 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}