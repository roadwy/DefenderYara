
rule TrojanSpy_Win32_Bancos_AJG{
	meta:
		description = "TrojanSpy:Win32/Bancos.AJG,SIGNATURE_TYPE_PEHSTR,05 00 05 00 04 00 00 02 00 "
		
	strings :
		$a_01_0 = {42 00 61 00 6e 00 63 00 6f 00 20 00 49 00 74 00 61 00 fa 00 20 00 2d 00 20 00 46 00 65 00 69 00 74 00 6f 00 20 00 50 00 61 00 72 00 61 00 20 00 56 00 6f 00 63 00 ea 00 20 00 2d 00 20 00 } //01 00 
		$a_01_1 = {70 00 72 00 61 00 6b 00 65 00 69 00 6d 00 3d 00 61 00 6e 00 74 00 6f 00 6e 00 69 00 6f 00 2e 00 6d 00 61 00 72 00 71 00 75 00 65 00 73 00 31 00 35 00 33 00 33 00 40 00 67 00 6d 00 61 00 69 00 6c 00 2e 00 63 00 6f 00 6d 00 } //01 00  prakeim=antonio.marques1533@gmail.com
		$a_01_2 = {70 00 72 00 61 00 6b 00 65 00 69 00 6d 00 3d 00 6d 00 61 00 67 00 6f 00 2e 00 69 00 6e 00 66 00 6f 00 73 00 30 00 32 00 40 00 67 00 6d 00 61 00 69 00 6c 00 2e 00 63 00 6f 00 6d 00 } //02 00  prakeim=mago.infos02@gmail.com
		$a_01_3 = {8b 45 f0 c1 e0 06 03 d8 89 5d f0 83 c7 06 83 ff 08 7c 42 83 ef 08 8b cf 8b 5d f0 d3 eb 8b cf b8 01 00 00 00 d3 e0 8b c8 8b 45 f0 99 f7 f9 } //00 00 
	condition:
		any of ($a_*)
 
}