
rule Trojan_Win32_Phosae_B_dha{
	meta:
		description = "Trojan:Win32/Phosae.B!dha,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {30 78 38 37 61 31 34 35 66 32 2c 20 30 78 39 30 34 34 2c 20 30 78 34 65 64 64 2c 20 30 78 62 39 2c 20 30 78 39 66 2c 20 30 78 63 30 2c 20 30 78 65 39 2c 20 30 78 32 31 2c 20 30 78 61 30 2c 20 30 78 66 38 2c 20 30 78 35 31 } //1 0x87a145f2, 0x9044, 0x4edd, 0xb9, 0x9f, 0xc0, 0xe9, 0x21, 0xa0, 0xf8, 0x51
	condition:
		((#a_01_0  & 1)*1) >=1
 
}