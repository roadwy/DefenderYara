
rule TrojanDropper_Win32_Canahom_A{
	meta:
		description = "TrojanDropper:Win32/Canahom.A,SIGNATURE_TYPE_PEHSTR,01 00 01 00 02 00 00 "
		
	strings :
		$a_01_0 = {c7 85 84 fd ff ff 3c 44 14 13 8d 85 cc fc ff ff 50 ff 75 9c ff 15 34 4b 14 13 ff 75 9c ff 15 38 4b 14 13 5f } //1
		$a_01_1 = {ad 8b f7 33 c2 42 3d 53 6f 66 74 75 f3 4a ac 32 c2 aa 83 c2 02 e2 f6 68 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=1
 
}