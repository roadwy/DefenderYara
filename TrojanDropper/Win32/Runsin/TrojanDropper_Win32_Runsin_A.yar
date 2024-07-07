
rule TrojanDropper_Win32_Runsin_A{
	meta:
		description = "TrojanDropper:Win32/Runsin.A,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {76 0e 8b 45 e4 03 c1 80 30 90 01 01 41 3b 4d 90 01 01 72 f2 8d 45 bc 53 50 ff 75 90 01 01 ff 75 e4 ff 75 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}