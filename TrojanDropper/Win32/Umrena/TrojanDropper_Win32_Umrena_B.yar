
rule TrojanDropper_Win32_Umrena_B{
	meta:
		description = "TrojanDropper:Win32/Umrena.B,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {40 90 00 83 c1 01 3d 55 40 56 7c f2 31 c0 8d 85 00 ac 1e 50 68 04 01 00 00 e8 53 40 55 83 cf 00 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}