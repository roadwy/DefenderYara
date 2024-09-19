
rule Trojan_Win32_Remcos_AER_MTB{
	meta:
		description = "Trojan:Win32/Remcos.AER!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {57 56 83 c4 04 81 c7 1a 66 01 00 5f c6 85 2c f6 ff ff 56 c6 85 2d f6 ff ff 69 c6 85 2e f6 ff ff 72 c6 85 2f f6 ff ff 74 c6 85 30 f6 ff ff 75 c6 85 31 f6 ff ff 61 c6 85 32 f6 ff ff 6c c6 85 33 f6 ff ff 50 c6 85 34 f6 ff ff 72 c6 85 35 f6 ff ff 6f c6 85 36 f6 ff ff 74 c6 85 37 f6 ff ff 65 c6 85 38 f6 ff ff 63 c6 85 39 f6 ff ff 74 c6 85 3a f6 ff ff 00 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}