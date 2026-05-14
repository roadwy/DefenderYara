
rule Trojan_Win64_PoolInject_AHD_MTB{
	meta:
		description = "Trojan:Win64/PoolInject.AHD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,3c 00 3c 00 03 00 00 "
		
	strings :
		$a_03_0 = {41 0f af cb 44 03 ee 8d 14 09 0f be ?? ?? ?? ?? ?? 2b d3 41 03 d6 03 ca 0f } //30
		$a_01_1 = {89 44 24 38 8b 44 24 38 b9 0d f0 ad ba ba ef be ad de 85 c0 0f 45 ca } //20
		$a_01_2 = {53 74 6f 70 20 72 65 76 65 72 73 69 6e 67 20 74 68 65 20 62 69 6e 61 72 79 } //10 Stop reversing the binary
	condition:
		((#a_03_0  & 1)*30+(#a_01_1  & 1)*20+(#a_01_2  & 1)*10) >=60
 
}