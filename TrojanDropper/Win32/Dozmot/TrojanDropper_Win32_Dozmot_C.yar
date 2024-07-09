
rule TrojanDropper_Win32_Dozmot_C{
	meta:
		description = "TrojanDropper:Win32/Dozmot.C,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {99 b9 ff 00 00 00 f7 f9 80 fa 61 7e 05 80 fa 7a 7c 0a } //1
		$a_03_1 = {80 f9 41 7c 0d 80 f9 4d 7f 08 0f be c9 83 c1 ?? eb 1f } //2
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*2) >=3
 
}