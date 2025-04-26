
rule Trojan_Win32_Redline_GNX_MTB{
	meta:
		description = "Trojan:Win32/Redline.GNX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 7d 08 f6 17 80 07 ?? 80 2f ?? f6 2f 47 e2 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}