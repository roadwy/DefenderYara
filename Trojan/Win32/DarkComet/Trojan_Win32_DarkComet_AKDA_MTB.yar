
rule Trojan_Win32_DarkComet_AKDA_MTB{
	meta:
		description = "Trojan:Win32/DarkComet.AKDA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {b0 40 00 ff 15 ?? ?? ?? ?? a3 40 e9 40 00 85 c0 75 06 50 e8 ?? ?? ?? ?? 68 9c b0 40 00 50 ff 15 ?? ?? ?? ?? 83 3d 18 91 40 00 00 a3 44 e9 40 00 75 07 6a 00 e8 35 ?? 00 00 e8 50 ?? 00 00 6a 00 68 c0 10 40 00 68 b8 b0 40 00 6a 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}