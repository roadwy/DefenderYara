
rule TrojanDropper_Win32_Alnofs_A{
	meta:
		description = "TrojanDropper:Win32/Alnofs.A,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {6e 00 4d 5a 90 90 00 03 00 00 00 28 90 09 26 00 07 00 50 00 4c 00 55 00 47 00 49 00 4e 00 53 00 02 00 50 00 30 00 08 90 90 6d 00 61 00 69 00 6e 00 69 00 63 00 6f 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}