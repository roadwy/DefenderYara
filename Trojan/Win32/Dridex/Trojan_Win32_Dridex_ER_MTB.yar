
rule Trojan_Win32_Dridex_ER_MTB{
	meta:
		description = "Trojan:Win32/Dridex.ER!MTB,SIGNATURE_TYPE_PEHSTR,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_01_0 = {83 c0 01 83 c0 02 83 e8 02 cc 83 c0 02 83 e8 02 cc 83 c0 02 83 e8 02 cc 83 c0 02 83 e8 02 cc } //10
	condition:
		((#a_01_0  & 1)*10) >=10
 
}