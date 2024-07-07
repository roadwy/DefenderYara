
rule Trojan_Win32_Tibs_IU{
	meta:
		description = "Trojan:Win32/Tibs.IU,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_03_0 = {e8 00 00 00 00 cd 2c 74 90 01 01 8b 04 24 90 00 } //1
		$a_03_1 = {28 c0 c0 e4 07 31 db 90 03 03 04 80 38 4d 80 78 01 5a 74 0c 2d 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=1
 
}