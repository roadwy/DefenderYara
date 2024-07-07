
rule Trojan_Win32_Redline_ASCB_MTB{
	meta:
		description = "Trojan:Win32/Redline.ASCB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {ff 80 34 1e 90 01 01 83 c4 90 01 01 46 3b f7 0f 90 00 } //1
		$a_03_1 = {ff 80 04 1e 90 01 01 68 90 01 03 00 68 90 01 03 00 e8 90 01 02 ff ff 50 e8 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}