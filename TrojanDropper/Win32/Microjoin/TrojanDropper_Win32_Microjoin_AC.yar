
rule TrojanDropper_Win32_Microjoin_AC{
	meta:
		description = "TrojanDropper:Win32/Microjoin.AC,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {68 f4 01 00 00 90 66 57 66 33 ff 66 5f 55 8b 4b 1c 84 d2 74 4f 90 66 57 66 33 ff 66 5f d0 ea 72 33 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}