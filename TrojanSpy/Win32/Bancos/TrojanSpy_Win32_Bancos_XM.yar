
rule TrojanSpy_Win32_Bancos_XM{
	meta:
		description = "TrojanSpy:Win32/Bancos.XM,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 04 00 "
		
	strings :
		$a_01_0 = {70 72 61 71 75 65 3d 6a 75 73 74 75 73 2e 73 70 61 6d 65 72 2e 62 72 61 73 69 6c 40 67 6d 61 69 6c 2e 63 6f 6d } //01 00  praque=justus.spamer.brasil@gmail.com
		$a_01_1 = {53 65 74 2d 63 6f 6f 6b 69 65 } //00 00  Set-cookie
	condition:
		any of ($a_*)
 
}