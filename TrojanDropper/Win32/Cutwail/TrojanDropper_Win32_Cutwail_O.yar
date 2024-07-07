
rule TrojanDropper_Win32_Cutwail_O{
	meta:
		description = "TrojanDropper:Win32/Cutwail.O,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_02_0 = {10 50 e8 dd fe ff ff 83 c4 08 68 c8 00 00 00 8d 8d 38 ff ff ff 51 68 90 01 01 90 03 01 01 20 21 00 10 ff 15 90 00 } //1
		$a_02_1 = {10 52 e8 ed fe ff ff 83 c4 08 68 c8 00 00 00 8b 45 fc 50 68 90 01 01 51 00 10 ff 15 90 00 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=1
 
}