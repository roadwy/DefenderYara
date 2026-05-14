
rule Ransom_Win32_Locky_MX_MTB{
	meta:
		description = "Ransom:Win32/Locky.MX!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {52 83 c4 04 81 45 08 fb e5 d4 ff 21 75 dc 81 45 08 05 1a eb ff 33 fa c7 45 dc f0 01 40 00 3b f7 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}