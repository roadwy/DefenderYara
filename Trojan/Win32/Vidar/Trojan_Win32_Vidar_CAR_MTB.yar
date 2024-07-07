
rule Trojan_Win32_Vidar_CAR_MTB{
	meta:
		description = "Trojan:Win32/Vidar.CAR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {68 f1 f0 ad 0a ff 75 f0 e8 90 01 04 59 59 a3 78 c0 40 00 e8 90 01 04 68 64 18 2d 07 ff 75 f0 e8 90 01 04 59 59 a3 7c c0 40 00 e8 90 01 04 68 b5 3d 2c 06 ff 75 f0 e8 90 00 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}