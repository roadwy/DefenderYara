
rule Trojan_Win32_Gandcrab_CQS_MTB{
	meta:
		description = "Trojan:Win32/Gandcrab.CQS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {0a 44 3a 02 80 e4 fc c0 e3 ?? 0a 1c 3a c0 e4 ?? 0a 64 3a 01 83 c7 ?? 88 1c 31 88 64 31 01 88 44 31 02 83 c1 03 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}