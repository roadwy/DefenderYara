
rule Ransom_Win32_Magniber_RPY_MTB{
	meta:
		description = "Ransom:Win32/Magniber.RPY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 85 a8 fd ff ff 0f b7 8c 45 ac fd ff ff 83 f9 20 75 52 8b 85 a8 fd ff ff 0f b7 8c 45 ae fd ff ff 83 f9 2f 75 3f 8b 85 a8 fd ff ff 0f b7 8c 45 b0 fd ff ff 83 f9 64 75 2c 8b 85 a8 fd ff ff 0f b7 8c 45 b2 fd ff ff 83 f9 20 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}