
rule TrojanDropper_Win32_Boaxxe_C{
	meta:
		description = "TrojanDropper:Win32/Boaxxe.C,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {83 bd f0 fd ff ff 00 74 0d 8d 95 f8 fe ff ff 52 ff 15 90 01 02 40 00 83 7d 14 02 75 75 8d 45 f8 50 8d 8d f8 fe ff ff 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}