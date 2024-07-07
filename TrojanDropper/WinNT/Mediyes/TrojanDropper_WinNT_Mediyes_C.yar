
rule TrojanDropper_WinNT_Mediyes_C{
	meta:
		description = "TrojanDropper:WinNT/Mediyes.C,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {81 fe 38 04 00 00 76 0a bf 03 00 00 00 8b c7 5f 5e c3 83 f8 0a 75 40 81 fe ce 07 00 00 75 0a } //1
		$a_03_1 = {83 f8 68 74 90 02 02 e8 90 02 02 00 00 83 f8 90 01 01 74 90 01 01 e8 90 02 02 00 00 83 f8 6b 74 90 01 01 8b 85 90 01 02 ff ff 83 08 48 90 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}