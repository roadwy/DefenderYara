
rule Trojan_Win64_LummaStealer_SLBP_MTB{
	meta:
		description = "Trojan:Win64/LummaStealer.SLBP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {48 83 ec 38 48 8d 6c 24 30 0f 29 7d f0 0f 29 75 e0 48 8b 05 8c ad 02 00 48 31 e8 48 89 45 d8 8b 05 57 ba 02 00 8b 0d 55 ba 02 00 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}