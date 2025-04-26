
rule Trojan_Win32_Redline_RPN_MTB{
	meta:
		description = "Trojan:Win32/Redline.RPN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {33 d2 8b c1 f7 f6 80 c2 30 30 94 0d 47 ff ff ff 41 83 f9 0d 72 ea } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}