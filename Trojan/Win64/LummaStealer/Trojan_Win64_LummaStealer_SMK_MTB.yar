
rule Trojan_Win64_LummaStealer_SMK_MTB{
	meta:
		description = "Trojan:Win64/LummaStealer.SMK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {41 89 d4 41 89 cd 48 8b 05 f8 6d 03 00 48 31 e8 48 89 45 00 8b 05 cb 7b 03 00 8b 0d c9 7b 03 00 8d 50 ff } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}