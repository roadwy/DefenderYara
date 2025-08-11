
rule Trojan_Win64_LummaStealer_SHJI_MTB{
	meta:
		description = "Trojan:Win64/LummaStealer.SHJI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {48 83 ec 18 48 8d 6c 24 10 48 8b 05 a4 93 ff ff 48 31 e8 48 89 45 00 8b 0d 33 a4 ff ff 8b 05 31 a4 ff ff 8d 71 ff 0f af f1 89 f1 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}