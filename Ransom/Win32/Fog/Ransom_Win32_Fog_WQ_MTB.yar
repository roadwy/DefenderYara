
rule Ransom_Win32_Fog_WQ_MTB{
	meta:
		description = "Ransom:Win32/Fog.WQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {33 d2 f7 75 14 8b 45 10 0f b6 14 10 23 fa 0b f7 0b ce 8b 85 68 ff ff ff 03 45 98 88 08 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}