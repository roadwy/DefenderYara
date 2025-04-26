
rule Trojan_Win32_Redline_GCD_MTB{
	meta:
		description = "Trojan:Win32/Redline.GCD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {89 c2 0f b6 45 ca c1 e0 ?? 09 d0 88 45 ca 80 45 ca 0e f6 55 ca 80 45 ca 61 8b 45 f4 30 45 ca f6 5d ca 80 6d ca 3c f6 5d ca 8b 45 f4 00 45 ca f6 55 ca 8b 45 f4 30 45 ca 8b 45 f4 00 45 ca 8d 55 bb 8b 45 f4 01 c2 0f b6 45 ca 88 02 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}