
rule Trojan_Win32_Dialer_ADER_MTB{
	meta:
		description = "Trojan:Win32/Dialer.ADER!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {33 c0 8a 0c 30 80 f1 0a 88 0c 30 40 3d 4e 02 00 00 72 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}