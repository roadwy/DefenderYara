
rule TrojanDropper_Win32_Lisiu_A{
	meta:
		description = "TrojanDropper:Win32/Lisiu.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8d 4c 24 14 6a 00 51 8d 54 24 1b 8b f0 6a 01 52 56 c6 44 24 27 4d } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}