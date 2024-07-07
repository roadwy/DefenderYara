
rule TrojanDownloader_Win32_Vaprop_D{
	meta:
		description = "TrojanDownloader:Win32/Vaprop.D,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_11_0 = {00 62 00 6e 00 35 00 36 00 37 00 50 00 61 00 74 00 68 00 41 00 01 } //1 戀渀㔀㘀㜀倀愀琀栀䄀Ā
		$a_7b_1 = {31 00 66 00 34 00 64 00 65 00 33 00 37 00 30 00 2d } //19456
	condition:
		((#a_11_0  & 1)*1+(#a_7b_1  & 1)*19456) >=3
 
}