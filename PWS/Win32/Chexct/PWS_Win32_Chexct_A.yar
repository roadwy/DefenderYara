
rule PWS_Win32_Chexct_A{
	meta:
		description = "PWS:Win32/Chexct.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {25 73 3f 75 6e 3d 25 73 26 70 6e 3d 25 73 5f 25 30 32 64 25 30 32 64 25 30 32 64 25 30 32 64 5f 25 64 2e 6a 70 67 } //1 %s?un=%s&pn=%s_%02d%02d%02d%02d_%d.jpg
		$a_00_1 = {3f 61 74 3d 75 70 6d 26 } //1 ?at=upm&
		$a_03_2 = {6a 40 6a 06 56 ff 15 ?? ?? ?? ?? 8b 45 0c c6 06 68 89 46 01 c6 46 05 c3 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}