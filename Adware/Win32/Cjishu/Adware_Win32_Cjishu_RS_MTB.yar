
rule Adware_Win32_Cjishu_RS_MTB{
	meta:
		description = "Adware:Win32/Cjishu.RS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_80_0 = {63 6a 69 73 68 75 2e 63 6f 6d } //cjishu.com  01 00 
		$a_80_1 = {73 6f 66 74 69 6e 66 6f 2e 63 6e } //softinfo.cn  01 00 
		$a_80_2 = {53 4f 46 54 57 41 52 45 5c 47 72 61 62 73 75 6e } //SOFTWARE\Grabsun  01 00 
		$a_80_3 = {48 69 6e 74 73 6f 66 74 31 5c 58 75 6e 53 68 61 6e 50 72 6f } //Hintsoft1\XunShanPro  00 00 
	condition:
		any of ($a_*)
 
}