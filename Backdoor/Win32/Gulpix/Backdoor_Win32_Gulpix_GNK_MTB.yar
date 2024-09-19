
rule Backdoor_Win32_Gulpix_GNK_MTB{
	meta:
		description = "Backdoor:Win32/Gulpix.GNK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {30 f8 43 00 ee f7 43 00 ee f7 43 ?? ee f7 43 00 fe f7 43 ?? 30 f8 43 00 30 f8 43 00 14 f8 43 00 24 f8 43 00 30 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}