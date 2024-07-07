
rule TrojanSpy_Win32_Bancos_JL{
	meta:
		description = "TrojanSpy:Win32/Bancos.JL,SIGNATURE_TYPE_PEHSTR,0b 00 0b 00 03 00 00 "
		
	strings :
		$a_01_0 = {8b d8 4b 85 db 7c 65 8b 45 f0 c1 e0 06 03 d8 89 5d f0 83 c7 06 83 ff 08 7c 48 83 ef 08 8b cf 8b 5d f0 d3 eb 8b cf b8 01 00 00 00 d3 e0 50 8b 45 f0 5a 8b ca 99 f7 f9 89 55 f0 81 e3 ff 00 00 80 79 08 4b 81 cb 00 ff ff ff 43 } //10
		$a_01_1 = {5c 77 6d 70 72 66 50 54 42 2e 6c 6f 67 } //1 \wmprfPTB.log
		$a_01_2 = {2e 65 78 65 00 6f 70 65 6e 00 00 00 00 63 3a 5c } //1
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=11
 
}