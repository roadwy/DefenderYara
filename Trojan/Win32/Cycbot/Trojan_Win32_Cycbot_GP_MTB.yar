
rule Trojan_Win32_Cycbot_GP_MTB{
	meta:
		description = "Trojan:Win32/Cycbot.GP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {40 f0 c7 06 2d a9 55 1d e6 6a 24 72 7e c0 66 e0 ce b4 06 7d e4 0f f4 90 40 37 23 c0 ab ee b2 6e 41 82 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}