
rule Trojan_Win64_StrelaStealer_DAS_MTB{
	meta:
		description = "Trojan:Win64/StrelaStealer.DAS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {41 80 f2 ff 40 80 f6 00 44 88 cf 40 80 e7 00 40 20 f3 45 88 d6 41 80 e6 00 41 20 f3 40 08 df 45 08 de 44 30 f7 45 08 d1 41 80 f1 ff 40 80 ce 00 41 20 f1 44 08 cf 40 f6 c7 01 0f 85 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}