
rule Backdoor_Win32_Coroxy_CCHU_MTB{
	meta:
		description = "Backdoor:Win32/Coroxy.CCHU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 55 cc 03 55 ac 03 55 e8 2b d0 8b 45 d8 31 10 83 45 e8 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}