
rule Tampering_Win32_PPLClipUp_B{
	meta:
		description = "Tampering:Win32/PPLClipUp.B,SIGNATURE_TYPE_CMDHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_00_0 = {63 00 6c 00 69 00 70 00 75 00 70 00 2e 00 65 00 78 00 65 00 20 00 2d 00 70 00 70 00 6c 00 20 00 } //1 clipup.exe -ppl 
		$a_00_1 = {2e 00 74 00 6d 00 70 00 } //-5 .tmp
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*-5) >=1
 
}