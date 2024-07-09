
rule PWS_Win32_Frethog_MK_dll{
	meta:
		description = "PWS:Win32/Frethog.MK!dll,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 03 00 00 "
		
	strings :
		$a_00_0 = {26 68 69 64 64 65 6e 46 69 6c 65 3d 26 63 6f 66 66 65 72 2e 61 73 63 78 25 33 41 74 78 74 41 6d 6f 75 6e 74 3d } //1 &hiddenFile=&coffer.ascx%3AtxtAmount=
		$a_00_1 = {46 65 6e 47 61 6d 65 20 53 65 74 } //1 FenGame Set
		$a_02_2 = {8b c3 6a 05 99 59 f7 f9 85 d2 75 ?? 8a 45 10 8a 0c 37 d0 e0 2a c8 88 0e eb } //10
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_02_2  & 1)*10) >=12
 
}