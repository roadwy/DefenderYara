
rule TrojanDropper_Win32_Tnega_EA_MTB{
	meta:
		description = "TrojanDropper:Win32/Tnega.EA!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {f2 ae f7 d1 57 8d 3d 21 31 40 00 fc b0 00 b9 ff ff ff ff f2 ae f7 d1 8d 15 21 31 40 00 42 5f 4f 8a 02 88 07 47 42 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}