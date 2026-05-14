
rule Backdoor_Win32_Farfli_MK_MTB{
	meta:
		description = "Backdoor:Win32/Farfli.MK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,23 00 23 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f b7 44 51 08 8b e8 81 e5 ?? ?? 00 00 81 fd ?? ?? 00 00 75 10 25 ff 0f 00 00 03 01 8b ee 2b 6b ?? 03 c6 01 28 } //35
	condition:
		((#a_03_0  & 1)*35) >=35
 
}