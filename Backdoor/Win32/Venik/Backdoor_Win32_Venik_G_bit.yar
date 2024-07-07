
rule Backdoor_Win32_Venik_G_bit{
	meta:
		description = "Backdoor:Win32/Venik.G!bit,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {64 6e 61 6d 6d 6f 63 5c 6e 65 70 6f 5c 6c 6c 65 68 73 5c 65 78 65 2e 65 72 6f 6c 70 78 65 69 5c 73 6e 6f 69 74 61 63 69 6c 70 70 41 } //1 dnammoc\nepo\llehs\exe.erolpxei\snoitacilppA
		$a_01_1 = {25 73 25 34 64 2e 64 6c 6c } //1 %s%4d.dll
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}