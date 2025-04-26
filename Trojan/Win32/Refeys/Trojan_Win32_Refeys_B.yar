
rule Trojan_Win32_Refeys_B{
	meta:
		description = "Trojan:Win32/Refeys.B,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_01_0 = {26 63 6f 6d 6d 61 6e 64 3d 6b 6e 6f 63 6b 26 75 73 65 72 6e 61 6d 65 3d } //1 &command=knock&username=
		$a_01_1 = {26 63 6f 6d 6d 61 6e 64 3d 64 65 61 63 74 69 76 61 74 65 26 6d 6f 64 75 6c 65 3d 68 76 6e 63 } //1 &command=deactivate&module=hvnc
		$a_41_2 = {04 3e 3c 3b 74 0d 84 c0 74 09 42 88 04 33 46 3b f1 72 ec 01 } //1
		$a_63_3 = {6d } //6912 m
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_41_2  & 1)*1+(#a_63_3  & 1)*6912) >=3
 
}