
rule Trojan_Win32_LummaStealer_YIN_MTB{
	meta:
		description = "Trojan:Win32/LummaStealer.YIN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {2b cf 33 d7 2b cf 81 c7 cd 60 00 00 33 f8 2b f8 33 c7 33 d7 2b f8 03 ca b8 9b db cd 19 33 f9 69 d2 ?? ?? ?? ?? 33 fa 03 d1 81 f2 5e 00 00 00 03 fa 33 fa 66 81 ea 5e 0e 81 f0 f5 af a9 75 c7 85 00 fa ff ff 3a 0d 00 00 69 d2 b5 82 00 00 33 fa e9 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}