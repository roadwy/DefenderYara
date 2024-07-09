
rule Trojan_Win32_Doina_GXZ_MTB{
	meta:
		description = "Trojan:Win32/Doina.GXZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b c6 99 f7 7d f8 8b 4d 08 53 6a 01 8d 45 ff 6a 01 50 8a 14 0a 30 55 ff e8 ?? ?? ?? ?? 83 c4 10 46 57 e8 ?? ?? ?? ?? 83 c4 04 85 c0 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}