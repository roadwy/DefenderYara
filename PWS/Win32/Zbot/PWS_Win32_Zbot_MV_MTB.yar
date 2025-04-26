
rule PWS_Win32_Zbot_MV_MTB{
	meta:
		description = "PWS:Win32/Zbot.MV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {89 11 5d c3 90 0a 2e 00 8b ca a3 [0-04] 8b [0-05] 31 [0-05] a1 [0-04] a3 [0-04] 8b [0-05] 8b } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}