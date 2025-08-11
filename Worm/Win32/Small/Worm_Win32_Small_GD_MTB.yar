
rule Worm_Win32_Small_GD_MTB{
	meta:
		description = "Worm:Win32/Small.GD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {34 44 47 47 59 9c 31 cb b5 19 d1 31 0d ?? ?? ?? ?? 19 ec e4 52 2a c2 2c a5 6c 52 e2 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}