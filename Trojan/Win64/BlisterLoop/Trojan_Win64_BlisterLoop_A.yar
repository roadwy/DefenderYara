
rule Trojan_Win64_BlisterLoop_A{
	meta:
		description = "Trojan:Win64/BlisterLoop.A,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {b8 ff ff ff 7f 41 bc 01 00 00 00 89 45 40 f0 ff 4d 40 49 2b c4 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}