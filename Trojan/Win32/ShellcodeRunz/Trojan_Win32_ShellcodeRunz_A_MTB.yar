
rule Trojan_Win32_ShellcodeRunz_A_MTB{
	meta:
		description = "Trojan:Win32/ShellcodeRunz.A!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {1d bf a8 1d 1d bf a8 1d 1d bf a1 65 8e bf a6 1d 1d bf 6b 9e 1e be a1 1d 1d bf 6b 9e 19 be a4 1d 1d bf 6b 9e 18 be 80 1d 1d bf a8 1d 1c bf 15 1d 1d bf a8 1d 1d bf b5 1d 1d bf bc 99 e2 bf a9 1d 1d bf bc 99 1f be a9 1d 1d bf } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}