
rule Trojan_Win32_Hype_DSK_MTB{
	meta:
		description = "Trojan:Win32/Hype.DSK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_02_0 = {8a 14 1a 88 14 01 8a 8b 90 01 04 84 c9 75 90 01 01 8b 0d 90 01 04 8a 15 90 01 04 03 cb 03 c1 30 10 83 3d 90 01 04 03 76 90 00 } //2
	condition:
		((#a_02_0  & 1)*2) >=2
 
}