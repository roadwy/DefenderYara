
rule Ransom_Win32_Gandcrab_EN_MTB{
	meta:
		description = "Ransom:Win32/Gandcrab.EN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 01 00 00 "
		
	strings :
		$a_02_0 = {8d a4 24 00 00 00 00 90 90 0f b6 4c 85 d4 40 30 8a ?? ?? ?? ?? 33 c9 83 f8 0b 0f 44 c1 } //3
	condition:
		((#a_02_0  & 1)*3) >=3
 
}