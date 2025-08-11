
rule Trojan_Win64_LummaStealer_MZC_MTB{
	meta:
		description = "Trojan:Win64/LummaStealer.MZC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f b6 c1 8a 84 04 a0 01 00 00 48 63 4c 24 ?? 4c 8b 4c 24 38 41 30 04 09 44 8b 44 24 ?? 41 83 c0 01 b8 19 73 39 06 41 89 ef 41 ba 45 f3 d3 a7 be a6 f1 40 3e 41 bb fd 1d d5 f9 bd 86 7a 2c cf 41 bd e0 dd 42 3e 3d 87 3a 27 0b 0f 8f } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}