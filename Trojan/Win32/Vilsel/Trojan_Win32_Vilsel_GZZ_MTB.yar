
rule Trojan_Win32_Vilsel_GZZ_MTB{
	meta:
		description = "Trojan:Win32/Vilsel.GZZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {5a 09 1b 28 d1 5d 21 68 2d b7 b7 34 6c 40 c0 0e da 80 ad ?? ?? ?? ?? fe a7 ad e1 ad 2b 03 71 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}