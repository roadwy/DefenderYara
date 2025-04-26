
rule Ransom_Win32_Fog_SA{
	meta:
		description = "Ransom:Win32/Fog.SA,SIGNATURE_TYPE_CMDHSTR_EXT,28 00 28 00 04 00 00 "
		
	strings :
		$a_00_0 = {2d 00 6e 00 6f 00 6d 00 75 00 74 00 65 00 78 00 } //10 -nomutex
		$a_00_1 = {2d 00 73 00 69 00 7a 00 65 00 } //10 -size
		$a_00_2 = {2d 00 74 00 61 00 72 00 67 00 65 00 74 00 } //10 -target
		$a_00_3 = {5c 00 63 00 24 00 } //10 \c$
	condition:
		((#a_00_0  & 1)*10+(#a_00_1  & 1)*10+(#a_00_2  & 1)*10+(#a_00_3  & 1)*10) >=40
 
}