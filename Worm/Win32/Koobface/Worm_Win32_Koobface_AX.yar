
rule Worm_Win32_Koobface_AX{
	meta:
		description = "Worm:Win32/Koobface.AX,SIGNATURE_TYPE_PEHSTR,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {2f 2e 73 79 73 2e 70 68 70 } //2 /.sys.php
		$a_01_1 = {25 73 3f 61 25 73 6e 3d 25 73 67 65 6e 26 76 3d 25 73 } //1 %s?a%sn=%sgen&v=%s
		$a_01_2 = {43 72 65 61 74 65 49 45 20 32 20 62 65 67 69 6e } //1 CreateIE 2 begin
		$a_01_3 = {63 72 79 70 74 65 64 20 63 6f 64 65 20 64 65 74 65 63 74 65 64 } //1 crypted code detected
		$a_01_4 = {64 75 6d 70 20 72 65 73 70 6f 6e 63 65 } //1 dump responce
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}