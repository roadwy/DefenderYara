
rule Trojan_Win32_LummaStealz_B_MTB{
	meta:
		description = "Trojan:Win32/LummaStealz.B!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_81_0 = {6c 69 64 3d 25 73 26 6a 3d 25 73 26 76 65 72 3d } //1 lid=%s&j=%s&ver=
		$a_00_1 = {38 39 ca 83 e2 03 8a 54 14 08 32 54 0d 04 } //1
	condition:
		((#a_81_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}