
rule Trojan_Win32_Upatre_RPA_MTB{
	meta:
		description = "Trojan:Win32/Upatre.RPA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {83 c4 04 50 56 56 83 2c 24 01 01 04 24 5e 8b 36 56 59 58 8b f0 58 83 ea 01 80 f1 f1 c0 c1 05 80 e9 05 8a d8 fe cb 80 e3 01 32 cb 56 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}