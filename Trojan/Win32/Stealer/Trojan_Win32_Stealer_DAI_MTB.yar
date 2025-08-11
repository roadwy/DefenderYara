
rule Trojan_Win32_Stealer_DAI_MTB{
	meta:
		description = "Trojan:Win32/Stealer.DAI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 4d 08 30 04 0f 47 3b 7d 0c 0f 82 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}