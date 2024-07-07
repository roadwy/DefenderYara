
rule TrojanSpy_Win32_Festeal_A{
	meta:
		description = "TrojanSpy:Win32/Festeal.A,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {b8 bf cf ff db ff 08 8b ea 6a ff 6a 02 e8 0d 02 54 8b f0 83 fe ff 74 f0 57 56 48 b3 fd b3 ff eb } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}