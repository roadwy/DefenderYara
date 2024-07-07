
rule PWS_Win32_QQpass_EG{
	meta:
		description = "PWS:Win32/QQpass.EG,SIGNATURE_TYPE_PEHSTR_EXT,06 00 05 00 06 00 00 "
		
	strings :
		$a_01_0 = {26 71 71 70 61 73 73 77 6f 72 64 3d } //1 &qqpassword=
		$a_01_1 = {3f 71 71 6e 75 6d 62 65 72 3d } //1 ?qqnumber=
		$a_01_2 = {5c 42 69 6e 5c 71 71 64 61 74 2e 65 78 65 } //1 \Bin\qqdat.exe
		$a_01_3 = {26 50 63 61 63 68 65 54 69 6d 65 3d 31 32 31 36 32 39 37 37 31 33 } //1 &PcacheTime=1216297713
		$a_01_4 = {79 69 79 75 79 61 6e } //1 yiyuyan
		$a_01_5 = {51 ce d2 b0 c9 cd bc b1 ea } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=5
 
}