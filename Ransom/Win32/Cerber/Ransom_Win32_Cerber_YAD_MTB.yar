
rule Ransom_Win32_Cerber_YAD_MTB{
	meta:
		description = "Ransom:Win32/Cerber.YAD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b 55 b4 8b 45 dc 23 05 ?? ?? ?? ?? 33 c9 29 15 ?? ?? ?? ?? 8b 4d fc 31 55 d8 47 89 15 } //1
		$a_03_1 = {33 3d 60 96 40 00 03 3d 18 96 40 00 8b 55 08 f7 1d ?? ?? ?? ?? 03 f3 8b 45 0c 89 4d ec 8b 0d } //10
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*10) >=11
 
}