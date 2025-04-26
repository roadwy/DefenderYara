
rule PWS_Win32_Fareit_JK_MTB{
	meta:
		description = "PWS:Win32/Fareit.JK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {50 e8 f9 fe ?? ?? ba ?? ?? ?? ?? b8 ?? ?? ?? ?? 31 c9 80 34 01 fd 41 89 c9 39 d1 [0-02] 75 ?? 05 ?? ?? ?? ?? ff e0 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}