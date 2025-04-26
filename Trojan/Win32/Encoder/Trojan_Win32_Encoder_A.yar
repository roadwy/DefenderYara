
rule Trojan_Win32_Encoder_A{
	meta:
		description = "Trojan:Win32/Encoder.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {54 69 6c 65 57 61 6c 6c 70 61 70 65 72 } //1 TileWallpaper
		$a_00_1 = {30 35 38 36 33 30 38 39 30 34 33 32 37 31 33 31 } //2 0586308904327131
	condition:
		((#a_01_0  & 1)*1+(#a_00_1  & 1)*2) >=3
 
}