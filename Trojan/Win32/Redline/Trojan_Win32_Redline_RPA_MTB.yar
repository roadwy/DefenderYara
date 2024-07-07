
rule Trojan_Win32_Redline_RPA_MTB{
	meta:
		description = "Trojan:Win32/Redline.RPA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {33 c8 88 4d d2 8b 4d 0c 03 4d d4 8a 11 88 55 d3 0f be 45 d2 0f be 4d d3 03 c1 8b 55 0c 03 55 d4 88 02 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}