
rule Trojan_Win32_Shiz_EM_MTB{
	meta:
		description = "Trojan:Win32/Shiz.EM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 01 00 00 "
		
	strings :
		$a_01_0 = {33 dd be 33 1d 00 00 03 ee d1 e5 d1 c5 bb 23 1d 00 00 03 eb 45 33 f5 } //7
	condition:
		((#a_01_0  & 1)*7) >=7
 
}