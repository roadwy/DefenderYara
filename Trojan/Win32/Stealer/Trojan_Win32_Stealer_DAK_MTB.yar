
rule Trojan_Win32_Stealer_DAK_MTB{
	meta:
		description = "Trojan:Win32/Stealer.DAK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {8a c3 8d 0c 1a 2c ?? 30 41 0a 43 83 fb ?? 72 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}