
rule Backdoor_Win32_GodRat_CI_MTB{
	meta:
		description = "Backdoor:Win32/GodRat.CI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {8a 14 01 80 c2 41 80 f2 ?? 80 c2 41 80 f2 ?? 80 c2 41 80 f2 ?? 88 14 01 41 3b ce 7c } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}