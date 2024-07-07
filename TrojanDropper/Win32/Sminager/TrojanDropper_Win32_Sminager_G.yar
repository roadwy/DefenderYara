
rule TrojanDropper_Win32_Sminager_G{
	meta:
		description = "TrojanDropper:Win32/Sminager.G,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {50 61 74 68 3d 25 61 70 70 64 61 74 61 25 5c 6d 73 76 63 0d 0a 53 65 74 75 70 3d 6d 73 76 63 2e 76 62 73 0d 0a 53 69 6c 65 6e 74 3d 32 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}