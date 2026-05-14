
rule Trojan_Win32_HeavensGate_SX_MTB{
	meta:
		description = "Trojan:Win32/HeavensGate.SX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,32 00 32 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b ec 83 ec 0c 8b 45 ?? b9 10 27 00 00 f7 e1 f7 d8 83 d2 00 f7 da 89 45 } //30
		$a_01_1 = {c6 45 bc 5c c6 45 bd 41 c6 45 be 70 c6 45 bf 70 c6 45 c0 44 c6 45 c1 61 c6 45 c2 74 c6 45 c3 61 c6 45 c4 5c c6 45 c5 4c c6 45 c6 6f c6 45 c7 63 c6 45 c8 61 c6 45 c9 6c c6 45 ca 5c c6 45 cb 53 c6 45 cc 74 c6 45 cd 65 c6 45 ce 61 c6 45 cf 6d c6 45 d0 5c } //20
	condition:
		((#a_03_0  & 1)*30+(#a_01_1  & 1)*20) >=50
 
}