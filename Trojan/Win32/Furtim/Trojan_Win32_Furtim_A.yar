
rule Trojan_Win32_Furtim_A{
	meta:
		description = "Trojan:Win32/Furtim.A,SIGNATURE_TYPE_PEHSTR_EXT,64 00 64 00 01 00 00 "
		
	strings :
		$a_03_0 = {33 d2 3a cb 74 30 8b 45 90 01 01 8a 80 90 01 04 88 45 90 01 01 8a 45 90 01 01 f6 ea 02 c1 30 45 90 01 01 8a 8a 90 01 04 42 3a cb 75 eb 8a 45 90 01 01 8b 4d 90 01 01 88 81 90 01 04 8b 45 90 01 01 ff 45 90 01 01 39 45 90 01 01 72 bc 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=100
 
}