
rule Trojan_Win32_BuhTrap_MK_MTB{
	meta:
		description = "Trojan:Win32/BuhTrap.MK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,23 00 23 00 01 00 00 "
		
	strings :
		$a_01_0 = {0f 10 44 02 c0 66 0f fc c1 0f 11 40 c0 0f 10 44 07 c0 66 0f fc c1 0f 11 40 d0 0f 10 44 03 c0 66 0f fc c1 0f 11 40 e0 0f 10 44 06 c0 66 0f fc c1 0f 11 40 f0 83 e9 01 } //35
	condition:
		((#a_01_0  & 1)*35) >=35
 
}