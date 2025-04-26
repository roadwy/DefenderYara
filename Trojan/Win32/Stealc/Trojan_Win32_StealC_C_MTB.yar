
rule Trojan_Win32_StealC_C_MTB{
	meta:
		description = "Trojan:Win32/StealC.C!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {81 ad 3c ff ff ff 02 6e 7c 7c 81 6d b0 ab ac 55 11 81 45 c0 a3 a6 28 6b 81 45 c0 07 93 a9 39 81 45 a4 48 19 ae 48 81 45 e0 ee 58 f0 51 81 85 68 ff ff ff 08 c4 c6 51 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}