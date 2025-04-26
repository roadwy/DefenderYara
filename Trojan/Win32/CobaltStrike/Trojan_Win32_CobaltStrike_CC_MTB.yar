
rule Trojan_Win32_CobaltStrike_CC_MTB{
	meta:
		description = "Trojan:Win32/CobaltStrike.CC!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {03 ce 0b d1 8b 0d d0 75 46 00 83 c1 fe 89 15 c4 75 46 00 03 ca 0b f1 8b 0d a4 75 46 00 89 35 60 75 46 00 31 3c 08 83 c0 04 8b 15 90 75 46 00 2b 15 64 75 46 00 33 15 64 75 46 00 8b 3d 84 75 46 00 81 f2 88 0f 0d 00 03 3d c0 75 46 00 89 15 64 75 46 00 89 3d 84 75 46 00 3d 44 03 00 00 0f 8c 47 ff ff ff } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}