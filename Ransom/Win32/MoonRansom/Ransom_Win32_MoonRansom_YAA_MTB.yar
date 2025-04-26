
rule Ransom_Win32_MoonRansom_YAA_MTB{
	meta:
		description = "Ransom:Win32/MoonRansom.YAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 "
		
	strings :
		$a_01_0 = {83 66 40 00 33 c0 8a 04 30 30 04 1f ff 46 40 47 8b 46 40 } //10
		$a_01_1 = {8a 44 35 dc 8b 4d d8 32 c8 88 4c 35 dc 46 } //1
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*1) >=11
 
}