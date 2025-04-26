
rule Trojan_Win32_PonyStealer_DAC_MTB{
	meta:
		description = "Trojan:Win32/PonyStealer.DAC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {80 ff 66 31 34 24 3c 23 80 fd f4 66 81 fb ed 8f 58 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}