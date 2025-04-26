
rule Trojan_Win32_FormBook_ARN_MTB{
	meta:
		description = "Trojan:Win32/FormBook.ARN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 45 f8 99 b9 ?? ?? ?? ?? f7 f9 8b 45 e4 0f b6 0c 10 8b 55 dc 03 55 f8 0f b6 02 33 c1 8b 4d dc 03 4d f8 88 01 8b 55 f8 83 c2 01 89 55 f8 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}