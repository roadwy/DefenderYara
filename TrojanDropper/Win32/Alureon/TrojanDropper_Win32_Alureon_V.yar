
rule TrojanDropper_Win32_Alureon_V{
	meta:
		description = "TrojanDropper:Win32/Alureon.V,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {45 78 65 63 44 6f 73 2e 64 6c 6c 00 } //1
		$a_01_1 = {37 7a 61 2e 65 78 65 20 78 } //1 7za.exe x
		$a_01_2 = {61 31 2e 37 7a 20 2d 61 6f 61 20 2d 6f } //1 a1.7z -aoa -o
		$a_01_3 = {2d 70 6c 6f 6c 6d 69 6c 66 00 } //1 瀭潬浬汩f
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}